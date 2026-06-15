import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_chat.client_app import ClientSession
from secure_chat.crypto import (
    b64d,
    decrypt_e2e_message,
    encrypt_e2e_message,
    validate_certificate,
    verify_signed_prekey,
)
from secure_chat.profile import create_profile, load_profile
from secure_chat.server_app import SecureChatServer


class SocketFactory:
    def __init__(self, server):
        self.server = server

    def __call__(self, address):
        client_sock, server_sock = socket.socketpair()
        thread = threading.Thread(
            target=self.server._handle_connection,
            args=(server_sock, ("local", 0)),
            daemon=True,
        )
        thread.start()
        return client_sock


class IntegrationTest(unittest.TestCase):
    def _load_session(self, profile_path, password, ca_certificate_pem):
        profile = load_profile(profile_path, password)
        return profile, ClientSession("127.0.0.1", 9000, profile, ca_certificate_pem)

    def test_register_login_offline_delivery_and_forward_secrecy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = SecureChatServer("127.0.0.1", 9000, root / "server")
            ca_certificate_pem = (root / "server" / "ca_cert.pem").read_text(encoding="utf-8")

            alice_path = root / "alice.json"
            bob_path = root / "bob.json"
            create_profile(alice_path, "alice", b"segredo123")
            create_profile(bob_path, "bob", b"segredo123")

            try:
                with patch("socket.create_connection", new=SocketFactory(server)):
                    alice, alice_session = self._load_session(
                        alice_path,
                        b"segredo123",
                        ca_certificate_pem,
                    )
                    bob, bob_session = self._load_session(
                        bob_path,
                        b"segredo123",
                        ca_certificate_pem,
                    )

                    register_alice = alice_session.register()
                    register_bob = bob_session.register()
                    self.assertTrue(register_alice["ok"])
                    self.assertTrue(register_bob["ok"])

                    alice = load_profile(alice_path, b"segredo123")
                    bob = load_profile(bob_path, b"segredo123")
                    self.assertIsNotNone(alice.certificate_pem)
                    self.assertIsNotNone(bob.certificate_pem)

                    alice_identity = validate_certificate(
                        alice.certificate_pem,
                        ca_certificate_pem,
                        expected_common_name="alice",
                        require_encryption_key=True,
                    )
                    bob_identity = validate_certificate(
                        bob.certificate_pem,
                        ca_certificate_pem,
                        expected_common_name="bob",
                        require_encryption_key=True,
                    )
                    self.assertEqual(alice_identity.common_name, "alice")
                    self.assertEqual(bob_identity.common_name, "bob")

                    alice_session = ClientSession("127.0.0.1", 9000, alice, ca_certificate_pem)
                    alice_session.login()

                    bob_cert_response = alice_session.request(
                        {"type": "get_user_certificate", "username": "bob"}
                    )
                    self.assertTrue(bob_cert_response["ok"])
                    alice.upsert_contact("bob", bob_cert_response["certificate"])
                    alice.save()

                    bundle_response = alice_session.request(
                        {"type": "get_delivery_bundle", "username": "bob"}
                    )
                    self.assertTrue(bundle_response["ok"])
                    verify_signed_prekey(
                        "bob",
                        bundle_response["signed_prekey"],
                        b64d(bob_identity.signing_public_key_b64),
                    )

                    envelope = encrypt_e2e_message(
                        sender="alice",
                        recipient="bob",
                        message_text="ola bob offline",
                        sender_signing_private_key=alice.signing_private_key,
                        sender_certificate_pem=alice.certificate_pem,
                        sender_identity_private_key=alice.encryption_private_key,
                        recipient_signing_public_key_raw=b64d(bob_identity.signing_public_key_b64),
                        recipient_identity_public_key_raw=b64d(
                            bob_identity.encryption_public_key_b64
                        ),
                        recipient_signed_prekey=bundle_response["signed_prekey"],
                        recipient_one_time_prekey=bundle_response["one_time_prekey"],
                        sent_at="2026-04-24T00:00:00+00:00",
                    )
                    send_response = alice_session.request(
                        {"type": "send_message", "recipient": "bob", "envelope": envelope}
                    )
                    self.assertTrue(send_response["ok"])
                    alice_session.close()

                    bob, bob_session = self._load_session(
                        bob_path,
                        b"segredo123",
                        ca_certificate_pem,
                    )
                    bob_session.login()
                    fetched = bob_session.request({"type": "fetch_messages"})
                    self.assertEqual(len(fetched["messages"]), 1)
                    message = fetched["messages"][0]

                    payload, sender_identity = decrypt_e2e_message(
                        message["envelope"],
                        bob.encryption_private_key,
                        bob.get_signed_prekey_private(
                            message["envelope"]["recipient_signed_prekey_id"]
                        ),
                        bob.get_one_time_prekey_private(
                            message["envelope"]["recipient_one_time_prekey_id"]
                        ),
                        ca_certificate_pem,
                    )
                    self.assertEqual(payload["message"], "ola bob offline")
                    self.assertEqual(sender_identity.common_name, "alice")

                    used_one_time_prekey_id = message["envelope"]["recipient_one_time_prekey_id"]
                    used_signed_prekey_id = message["envelope"]["recipient_signed_prekey_id"]
                    bob.remove_one_time_prekey(used_one_time_prekey_id)
                    bob.save()

                    ack_response = bob_session.request(
                        {"type": "ack_messages", "ids": [message["id"]]}
                    )
                    self.assertEqual(ack_response["acked"], 1)
                    self.assertEqual(
                        bob_session.request({"type": "fetch_messages"})["messages"], []
                    )

                    compromised_bob = load_profile(bob_path, b"segredo123")
                    self.assertIsNotNone(
                        compromised_bob.get_signed_prekey_private(used_signed_prekey_id)
                    )
                    self.assertIsNone(
                        compromised_bob.get_one_time_prekey_private(used_one_time_prekey_id)
                    )
                    with self.assertRaises(ValueError):
                        decrypt_e2e_message(
                            message["envelope"],
                            compromised_bob.encryption_private_key,
                            compromised_bob.get_signed_prekey_private(used_signed_prekey_id),
                            compromised_bob.get_one_time_prekey_private(
                                used_one_time_prekey_id
                            ),
                            ca_certificate_pem,
                        )

                    bob_session.close()
            finally:
                server.close()

    def test_rejects_inconsistent_e2e_envelope_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = SecureChatServer("127.0.0.1", 9000, root / "server")
            ca_certificate_pem = (root / "server" / "ca_cert.pem").read_text(encoding="utf-8")

            alice_path = root / "alice.json"
            bob_path = root / "bob.json"
            create_profile(alice_path, "alice", b"segredo123")
            create_profile(bob_path, "bob", b"segredo123")

            try:
                with patch("socket.create_connection", new=SocketFactory(server)):
                    alice, alice_session = self._load_session(
                        alice_path,
                        b"segredo123",
                        ca_certificate_pem,
                    )
                    bob, bob_session = self._load_session(
                        bob_path,
                        b"segredo123",
                        ca_certificate_pem,
                    )

                    self.assertTrue(alice_session.register()["ok"])
                    self.assertTrue(bob_session.register()["ok"])

                    alice = load_profile(alice_path, b"segredo123")
                    bob = load_profile(bob_path, b"segredo123")
                    bob_identity = validate_certificate(
                        bob.certificate_pem,
                        ca_certificate_pem,
                        expected_common_name="bob",
                        require_encryption_key=True,
                    )

                    alice_session = ClientSession("127.0.0.1", 9000, alice, ca_certificate_pem)
                    bob_session = ClientSession("127.0.0.1", 9000, bob, ca_certificate_pem)
                    alice_session.login()
                    bob_session.login()

                    bundle = alice_session.request(
                        {"type": "get_delivery_bundle", "username": "bob"}
                    )

                    wrong_recipient_envelope = encrypt_e2e_message(
                        sender="alice",
                        recipient="bob",
                        message_text="ola bob",
                        sender_signing_private_key=alice.signing_private_key,
                        sender_certificate_pem=alice.certificate_pem,
                        sender_identity_private_key=alice.encryption_private_key,
                        recipient_signing_public_key_raw=b64d(bob_identity.signing_public_key_b64),
                        recipient_identity_public_key_raw=b64d(
                            bob_identity.encryption_public_key_b64
                        ),
                        recipient_signed_prekey=bundle["signed_prekey"],
                        recipient_one_time_prekey=bundle["one_time_prekey"],
                        sent_at="2026-04-24T00:00:00+00:00",
                    )
                    wrong_recipient_envelope["recipient"] = "mallory"
                    response = alice_session.request(
                        {
                            "type": "send_message",
                            "recipient": "bob",
                            "envelope": wrong_recipient_envelope,
                        }
                    )
                    self.assertFalse(response["ok"])
                    self.assertIn("recipient", response["message"])

                    next_bundle = alice_session.request(
                        {"type": "get_delivery_bundle", "username": "bob"}
                    )
                    wrong_sender_envelope = encrypt_e2e_message(
                        sender="alice",
                        recipient="bob",
                        message_text="ola bob",
                        sender_signing_private_key=alice.signing_private_key,
                        sender_certificate_pem=alice.certificate_pem,
                        sender_identity_private_key=alice.encryption_private_key,
                        recipient_signing_public_key_raw=b64d(bob_identity.signing_public_key_b64),
                        recipient_identity_public_key_raw=b64d(
                            bob_identity.encryption_public_key_b64
                        ),
                        recipient_signed_prekey=next_bundle["signed_prekey"],
                        recipient_one_time_prekey=next_bundle["one_time_prekey"],
                        sent_at="2026-04-24T00:00:00+00:00",
                    )
                    wrong_sender_envelope["sender"] = "mallory"
                    response = alice_session.request(
                        {
                            "type": "send_message",
                            "recipient": "bob",
                            "envelope": wrong_sender_envelope,
                        }
                    )
                    self.assertFalse(response["ok"])
                    self.assertIn("sender", response["message"])

                    self.assertEqual(
                        bob_session.request({"type": "fetch_messages"})["messages"], []
                    )

                    alice_session.close()
                    bob_session.close()
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
