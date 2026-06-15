import json
import os
import re
import socket
import threading
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .crypto import (
    SERVER_CERT_COMMON_NAME,
    b64d,
    b64e,
    build_registration_proof_payload,
    build_server_signature_payload,
    build_session_keys,
    certificate_fingerprint,
    create_root_ca,
    extract_certificate_identity,
    fingerprint,
    generate_ed25519_private_key,
    generate_x25519_private_key,
    issue_leaf_certificate,
    load_ed25519_private_key,
    load_ed25519_public_key,
    load_x25519_public_key,
    serialize_ed25519_private_key,
    serialize_x25519_public_key,
    sign_payload,
    validate_certificate,
    verify_signature,
    verify_signed_prekey,
)
from .framing import recv_json, send_json
from .session import ProtocolError, SecureChannel
from .storage import ServerDatabase
from .utils import ensure_parent_dir

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def load_or_create_ca(data_dir):
    data_dir = Path(data_dir).expanduser().resolve()
    ensure_parent_dir(data_dir / "ca_identity.json")
    identity_path = data_dir / "ca_identity.json"
    cert_path = data_dir / "ca_cert.pem"

    if identity_path.exists():
        data = json.loads(identity_path.read_text(encoding="utf-8"))
        private_key = load_ed25519_private_key(b64d(data["private_key"]))
        certificate_pem = data["certificate_pem"]
        cert_path.write_text(certificate_pem, encoding="utf-8")
        return private_key, certificate_pem, cert_path

    private_key, certificate_pem = create_root_ca()
    identity_path.write_text(
        json.dumps(
            {
                "private_key": b64e(serialize_ed25519_private_key(private_key)),
                "certificate_pem": certificate_pem,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    cert_path.write_text(certificate_pem, encoding="utf-8")
    return private_key, certificate_pem, cert_path


def load_or_create_server_identity(data_dir, ca_private_key, ca_certificate_pem):
    data_dir = Path(data_dir).expanduser().resolve()
    ensure_parent_dir(data_dir / "server_identity.json")
    identity_path = data_dir / "server_identity.json"
    cert_path = data_dir / "server_cert.pem"

    if identity_path.exists():
        data = json.loads(identity_path.read_text(encoding="utf-8"))
        private_key = load_ed25519_private_key(b64d(data["private_key"]))
        certificate_pem = data["certificate_pem"]
        cert_path.write_text(certificate_pem, encoding="utf-8")
        return private_key, certificate_pem, cert_path

    private_key = generate_ed25519_private_key()
    certificate_pem = issue_leaf_certificate(
        ca_private_key,
        ca_certificate_pem,
        SERVER_CERT_COMMON_NAME,
        private_key.public_key(),
    )
    identity_path.write_text(
        json.dumps(
            {
                "private_key": b64e(serialize_ed25519_private_key(private_key)),
                "certificate_pem": certificate_pem,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    cert_path.write_text(certificate_pem, encoding="utf-8")
    return private_key, certificate_pem, cert_path


class SecureChatServer:
    def __init__(self, host, port, data_dir):
        self.host = host
        self.port = port
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.ca_private_key, self.ca_certificate_pem, self.ca_certificate_path = (
            load_or_create_ca(self.data_dir)
        )
        self.server_signing_private_key, self.server_certificate_pem, self.server_certificate_path = (
            load_or_create_server_identity(
                self.data_dir,
                self.ca_private_key,
                self.ca_certificate_pem,
            )
        )
        self.database = ServerDatabase(self.data_dir / "server.db")
        self._shutdown = threading.Event()

    def close(self):
        self._shutdown.set()
        self.database.close()

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"Servidor a ouvir em {self.host}:{self.port}")
            print(f"CA raiz: {self.ca_certificate_path}")
            print(f"Certificado do servidor: {self.server_certificate_path}")

            while not self._shutdown.is_set():
                try:
                    conn, addr = server_socket.accept()
                except OSError:
                    break
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True,
                ).start()

    def _handle_connection(self, conn, addr):
        with conn:
            try:
                client_hello = recv_json(conn)
                self._validate_client_hello(client_hello)
                channel, server_hello_unsigned = self._perform_handshake(conn, client_hello)

                if client_hello["mode"] == "register":
                    self._handle_register(channel, client_hello)
                    return

                username = self._handle_login(channel, client_hello, server_hello_unsigned)
                self._serve_authenticated_session(channel, username)
            except (ConnectionError, ProtocolError, ValueError, InvalidSignature) as exc:
                print(f"[{addr[0]}:{addr[1]}] Ligacao terminada: {exc}")

    def _validate_client_hello(self, client_hello):
        required = {"version", "mode", "username", "client_ephemeral_public_key"}
        if not required.issubset(client_hello):
            raise ProtocolError("Client hello incompleto.")
        if client_hello["version"] != 2:
            raise ProtocolError("Versao de protocolo nao suportada.")
        if client_hello["mode"] not in {"register", "login"}:
            raise ProtocolError("Modo de handshake invalido.")
        if not USERNAME_RE.fullmatch(client_hello["username"]):
            raise ProtocolError("Username invalido.")

    def _perform_handshake(self, conn, client_hello):
        server_ephemeral_private_key = generate_x25519_private_key()
        server_hello_unsigned = {
            "version": 2,
            "server_ephemeral_public_key": b64e(
                serialize_x25519_public_key(server_ephemeral_private_key.public_key())
            ),
            "server_nonce": b64e(os.urandom(16)),
            "server_certificate": self.server_certificate_pem,
            "server_certificate_fingerprint": certificate_fingerprint(self.server_certificate_pem),
        }
        signature_payload = build_server_signature_payload(client_hello, server_hello_unsigned)
        server_hello = {
            **server_hello_unsigned,
            "server_signature": b64e(
                sign_payload(self.server_signing_private_key, signature_payload)
            ),
        }
        send_json(conn, server_hello)

        shared_secret = server_ephemeral_private_key.exchange(
            load_x25519_public_key(b64d(client_hello["client_ephemeral_public_key"]))
        )
        session_keys = build_session_keys(
            shared_secret,
            client_hello,
            server_hello_unsigned,
            is_client=False,
        )
        return SecureChannel(conn, **session_keys), server_hello_unsigned

    def _issue_or_reuse_user_certificate(self, username, signing_public_key_b64, encryption_public_key_b64):
        existing_record = self.database.get_user_record(username)
        if existing_record:
            identity = validate_certificate(
                existing_record["certificate_pem"],
                self.ca_certificate_pem,
                expected_common_name=username,
                require_encryption_key=True,
            )
            if (
                identity.signing_public_key_b64 != signing_public_key_b64
                or identity.encryption_public_key_b64 != encryption_public_key_b64
            ):
                return False, None, "O username ja existe com outras chaves/certificado."
            return True, existing_record["certificate_pem"], "Utilizador ja registado com o mesmo certificado."

        certificate_pem = issue_leaf_certificate(
            self.ca_private_key,
            self.ca_certificate_pem,
            username,
            load_ed25519_public_key(b64d(signing_public_key_b64)),
            identity_encryption_public_key_raw=b64d(encryption_public_key_b64),
        )
        ok, message = self.database.register_user(username, certificate_pem)
        if not ok:
            return False, None, message
        return True, certificate_pem, message

    def _store_prekeys_for_user(self, username, signing_public_key_raw, signed_prekey, one_time_prekeys):
        verify_signed_prekey(username, signed_prekey, signing_public_key_raw)
        for item in one_time_prekeys:
            required = {"key_id", "public_key", "created_at"}
            if not required.issubset(item):
                raise ProtocolError("One-time prekey incompleta.")
            load_x25519_public_key(b64d(item["public_key"]))

        self.database.upsert_signed_prekey(username, signed_prekey)
        return self.database.store_one_time_prekeys(username, one_time_prekeys)

    def _handle_register(self, channel, client_hello):
        request = channel.recv()
        if request.get("type") != "register_user":
            raise ProtocolError("Pedido de registo invalido.")
        if request.get("username") != client_hello["username"]:
            raise ProtocolError("Username inconsistente no registo.")

        required = {
            "signing_public_key",
            "encryption_public_key",
            "registration_proof",
            "signed_prekey",
            "one_time_prekeys",
        }
        if not required.issubset(request):
            raise ProtocolError("Pedido de registo incompleto.")

        signing_public_key_raw = b64d(request["signing_public_key"])
        load_ed25519_public_key(signing_public_key_raw)
        load_x25519_public_key(b64d(request["encryption_public_key"]))
        verify_signature(
            load_ed25519_public_key(signing_public_key_raw),
            b64d(request["registration_proof"]),
            build_registration_proof_payload(
                request["username"],
                request["signing_public_key"],
                request["encryption_public_key"],
            ),
        )

        ok, certificate_pem, message = self._issue_or_reuse_user_certificate(
            request["username"],
            request["signing_public_key"],
            request["encryption_public_key"],
        )
        if not ok:
            channel.send({"ok": False, "message": message})
            return

        uploaded_ids = self._store_prekeys_for_user(
            request["username"],
            signing_public_key_raw,
            request["signed_prekey"],
            request.get("one_time_prekeys", []),
        )
        if request.get("contacts_blob") is not None:
            self.database.save_contacts_blob(request["username"], request["contacts_blob"])

        channel.send(
            {
                "ok": True,
                "message": message,
                "certificate": certificate_pem,
                "uploaded_one_time_prekeys": uploaded_ids,
            }
        )

    def _handle_login(self, channel, client_hello, server_hello_unsigned):
        request = channel.recv()
        if request.get("type") != "login_auth":
            raise ProtocolError("Pedido de autenticacao invalido.")

        record = self.database.get_user_record(client_hello["username"])
        if not record:
            channel.send({"ok": False, "message": "Utilizador nao registado."})
            raise ProtocolError("Tentativa de login para utilizador desconhecido.")

        identity = validate_certificate(
            record["certificate_pem"],
            self.ca_certificate_pem,
            expected_common_name=client_hello["username"],
            require_encryption_key=True,
        )
        verify_signature(
            load_ed25519_public_key(b64d(identity.signing_public_key_b64)),
            b64d(request["client_signature"]),
            build_server_signature_payload(client_hello, server_hello_unsigned),
        )

        channel.send(
            {
                "ok": True,
                "message": f"Sessao autenticada para {client_hello['username']}.",
            }
        )
        return client_hello["username"]

    def _serve_authenticated_session(self, channel, username):
        while True:
            request = channel.recv()
            response = self._dispatch_request(username, request)
            channel.send(response)
            if request.get("type") == "logout":
                return

    def _dispatch_request(self, username, request):
        req_type = request.get("type")

        if req_type == "ping":
            return {"ok": True, "message": "pong"}

        if req_type == "logout":
            return {"ok": True, "message": "Sessao terminada."}

        if req_type == "list_users":
            users = self.database.list_users()
            return {"ok": True, "users": users}

        if req_type == "get_user_certificate":
            certificate_pem = self.database.get_user_certificate(request["username"])
            if not certificate_pem:
                return {"ok": False, "message": "Utilizador desconhecido."}
            return {"ok": True, "certificate": certificate_pem}

        if req_type == "get_contacts_blob":
            blob = self.database.load_contacts_blob(username)
            return {"ok": True, "contacts_blob": blob}

        if req_type == "set_contacts_blob":
            self.database.save_contacts_blob(username, request["contacts_blob"])
            return {"ok": True, "message": "Contactos sincronizados."}

        if req_type == "publish_prekeys":
            record = self.database.get_user_record(username)
            identity = extract_certificate_identity(record["certificate_pem"])
            uploaded_ids = self._store_prekeys_for_user(
                username,
                b64d(identity.signing_public_key_b64),
                request["signed_prekey"],
                request.get("one_time_prekeys", []),
            )
            remaining = self.database.count_one_time_prekeys(username)
            return {
                "ok": True,
                "uploaded_one_time_prekeys": uploaded_ids,
                "stored_one_time_prekeys": remaining,
            }

        if req_type == "get_delivery_bundle":
            bundle = self.database.acquire_delivery_bundle(request["username"])
            if not bundle:
                return {"ok": False, "message": "Utilizador desconhecido."}
            if bundle["signed_prekey"] is None:
                return {"ok": False, "message": "Destinatario sem signed prekey ativa."}
            if bundle["one_time_prekey"] is None:
                return {"ok": False, "message": "Destinatario sem one-time prekeys disponiveis."}
            return {"ok": True, **bundle}

        if req_type == "send_message":
            recipient = request["recipient"]
            if not self.database.get_user_record(recipient):
                return {"ok": False, "message": "Destinatario desconhecido."}
            envelope = request.get("envelope")
            if not isinstance(envelope, dict):
                return {"ok": False, "message": "Envelope E2EE invalido."}
            if envelope.get("sender") != username:
                return {
                    "ok": False,
                    "message": "Envelope inconsistente: sender nao coincide com a sessao.",
                }
            if envelope.get("recipient") != recipient:
                return {
                    "ok": False,
                    "message": "Envelope inconsistente: recipient nao coincide com o pedido.",
                }
            if envelope.get("scheme") is None or envelope.get("recipient_one_time_prekey_id") is None:
                return {"ok": False, "message": "Envelope E2EE incompleto."}
            message_id = self.database.store_message(
                recipient=recipient,
                sender=username,
                envelope=envelope,
            )
            return {"ok": True, "message_id": message_id}

        if req_type == "fetch_messages":
            messages = self.database.fetch_pending_messages(username)
            return {"ok": True, "messages": messages}

        if req_type == "ack_messages":
            count = self.database.ack_messages(username, request.get("ids", []))
            return {"ok": True, "acked": count}

        return {"ok": False, "message": "Pedido desconhecido."}
