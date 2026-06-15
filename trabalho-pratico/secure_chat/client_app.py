import argparse
import getpass
import socket
import shlex
from pathlib import Path

from .crypto import (
    SERVER_CERT_COMMON_NAME,
    b64d,
    b64e,
    build_registration_proof_payload,
    build_server_signature_payload,
    build_session_keys,
    decrypt_e2e_message,
    encrypt_e2e_message,
    fingerprint,
    generate_x25519_private_key,
    load_ed25519_public_key,
    load_x25519_public_key,
    serialize_x25519_public_key,
    sign_payload,
    validate_certificate,
    verify_signed_prekey,
    verify_signature,
)
from .framing import recv_json, send_json
from .profile import create_profile, load_profile
from .session import SecureChannel
from .utils import utc_now


def read_password(confirm=False):
    password = getpass.getpass("Password do perfil: ").encode()
    if confirm:
        confirmation = getpass.getpass("Confirmar password: ").encode()
        if password != confirmation:
            raise ValueError("As passwords nao coincidem.")
    return password


def load_ca_certificate(path):
    return Path(path).expanduser().resolve().read_text(encoding="utf-8")


class ClientSession:
    def __init__(self, host, port, profile, ca_certificate_pem):
        self.host = host
        self.port = port
        self.profile = profile
        self.ca_certificate_pem = ca_certificate_pem
        self.sock = None
        self.channel = None
        self.server_hello_unsigned = None
        self.client_hello = None

    def register(self):
        prekey_upload = self.profile.build_prekey_upload()
        self._open_secure_channel(mode="register")
        registration_proof = sign_payload(
            self.profile.signing_private_key,
            build_registration_proof_payload(
                self.profile.username,
                self.profile.signing_public_key_b64,
                self.profile.encryption_public_key_b64,
            ),
        )
        self.channel.send(
            {
                "type": "register_user",
                "username": self.profile.username,
                "signing_public_key": self.profile.signing_public_key_b64,
                "encryption_public_key": self.profile.encryption_public_key_b64,
                "registration_proof": b64e(registration_proof),
                "signed_prekey": prekey_upload["signed_prekey"],
                "one_time_prekeys": prekey_upload["one_time_prekeys"],
                "contacts_blob": self.profile.export_contacts_blob(),
            }
        )
        response = self.channel.recv()
        if response.get("ok"):
            self.profile.set_certificate(response["certificate"])
            self.profile.mark_prekeys_uploaded(response.get("uploaded_one_time_prekeys", []))
            self.profile.save()
        self.close()
        return response

    def login(self):
        self._open_secure_channel(mode="login")
        signature = sign_payload(
            self.profile.signing_private_key,
            build_server_signature_payload(self.client_hello, self.server_hello_unsigned),
        )
        self.channel.send(
            {
                "type": "login_auth",
                "client_signature": b64e(signature),
            }
        )
        response = self.channel.recv()
        if not response.get("ok"):
            self.close()
            raise RuntimeError(response["message"])

    def _open_secure_channel(self, mode):
        self.sock = socket.create_connection((self.host, self.port))
        client_ephemeral_private_key = generate_x25519_private_key()
        self.client_hello = {
            "version": 2,
            "mode": mode,
            "username": self.profile.username,
            "client_ephemeral_public_key": b64e(
                serialize_x25519_public_key(client_ephemeral_private_key.public_key())
            ),
        }
        send_json(self.sock, self.client_hello)
        server_hello = recv_json(self.sock)
        self.server_hello_unsigned = {
            "version": server_hello["version"],
            "server_ephemeral_public_key": server_hello["server_ephemeral_public_key"],
            "server_nonce": server_hello["server_nonce"],
            "server_certificate": server_hello["server_certificate"],
            "server_certificate_fingerprint": server_hello["server_certificate_fingerprint"],
        }
        server_identity = validate_certificate(
            server_hello["server_certificate"],
            self.ca_certificate_pem,
            expected_common_name=SERVER_CERT_COMMON_NAME,
            require_encryption_key=False,
        )
        verify_signature(
            load_ed25519_public_key(b64d(server_identity.signing_public_key_b64)),
            b64d(server_hello["server_signature"]),
            build_server_signature_payload(self.client_hello, self.server_hello_unsigned),
        )

        shared_secret = client_ephemeral_private_key.exchange(
            load_x25519_public_key(b64d(server_hello["server_ephemeral_public_key"]))
        )
        session_keys = build_session_keys(
            shared_secret,
            self.client_hello,
            self.server_hello_unsigned,
            is_client=True,
        )
        self.channel = SecureChannel(self.sock, **session_keys)

    def request(self, payload):
        self.channel.send(payload)
        return self.channel.recv()

    def close(self):
        try:
            if self.channel is not None:
                self.channel.send({"type": "logout"})
                self.channel.recv()
        except Exception:
            pass
        if self.sock is not None:
            self.sock.close()
        self.sock = None
        self.channel = None


class ClientShell:
    def __init__(self, session):
        self.session = session
        self.profile = session.profile
        self.ca_certificate_pem = session.ca_certificate_pem

    def sync_contacts(self):
        response = self.session.request({"type": "get_contacts_blob"})
        if response.get("contacts_blob"):
            self.profile.merge_remote_contacts_blob(response["contacts_blob"])

        self.profile.maybe_top_up_prekeys()
        prekey_upload = self.profile.build_prekey_upload()
        prekey_response = self.session.request(
            {
                "type": "publish_prekeys",
                "signed_prekey": prekey_upload["signed_prekey"],
                "one_time_prekeys": prekey_upload["one_time_prekeys"],
            }
        )
        self.profile.mark_prekeys_uploaded(prekey_response.get("uploaded_one_time_prekeys", []))
        self.profile.save()
        self.session.request(
            {
                "type": "set_contacts_blob",
                "contacts_blob": self.profile.export_contacts_blob(),
            }
        )

    def run(self):
        self.sync_contacts()
        print("Shell segura pronta. Escreve 'help' para ver os comandos.")

        while True:
            try:
                line = input(f"{self.profile.username}> ").strip()
            except EOFError:
                print()
                break

            if not line:
                continue

            try:
                if not self._handle_command(line):
                    break
            except Exception as exc:
                print(f"Erro: {exc}")

        self.profile.save()

    def _handle_command(self, line):
        parts = shlex.split(line)
        command = parts[0]

        if command == "help":
            print(
                "Comandos: help, whoami, users, contacts list, contacts add <user>, "
                "contacts remove <user>, send <user> <mensagem>, fetch, sync, quit"
            )
            return True

        if command == "whoami":
            print(self.profile.username)
            return True

        if command == "users":
            response = self.session.request({"type": "list_users"})
            for item in response["users"]:
                print(f"- {item['username']} ({item['registered_at']})")
            return True

        if command == "contacts":
            return self._handle_contacts(parts[1:])

        if command == "send":
            if len(parts) < 3:
                raise ValueError("Uso: send <utilizador> <mensagem>")
            recipient = parts[1]
            message = " ".join(parts[2:])
            self._send_message(recipient, message)
            return True

        if command == "fetch":
            self._fetch_messages()
            return True

        if command == "sync":
            self.sync_contacts()
            print("Contactos e prekeys sincronizados.")
            return True

        if command in {"quit", "exit"}:
            return False

        raise ValueError("Comando desconhecido.")

    def _handle_contacts(self, args):
        if not args:
            raise ValueError("Uso: contacts <list|add|remove> ...")

        subcommand = args[0]
        if subcommand == "list":
            contacts = self.profile.list_contacts()
            if not contacts:
                print("Sem contactos fixados.")
                return True
            for contact in contacts:
                identity = validate_certificate(
                    contact["certificate_pem"],
                    self.ca_certificate_pem,
                    expected_common_name=contact["username"],
                    require_encryption_key=True,
                )
                print(
                    f"- {contact['username']} "
                    f"(sign={fingerprint(b64d(identity.signing_public_key_b64))}, "
                    f"enc={fingerprint(b64d(identity.encryption_public_key_b64))})"
                )
            return True

        if subcommand == "add":
            if len(args) != 2:
                raise ValueError("Uso: contacts add <utilizador>")
            username = args[1]
            if username == self.profile.username:
                raise ValueError("Nao e possivel adicionar o proprio utilizador.")
            certificate_pem, identity = self._fetch_user_certificate(username)
            self.profile.upsert_contact(username, certificate_pem)
            self.profile.save()
            self.session.request(
                {
                    "type": "set_contacts_blob",
                    "contacts_blob": self.profile.export_contacts_blob(),
                }
            )
            print(
                f"Contacto {username} guardado. "
                f"Fingerprint assinatura={fingerprint(b64d(identity.signing_public_key_b64))}, "
                f"enc={fingerprint(b64d(identity.encryption_public_key_b64))}"
            )
            return True

        if subcommand == "remove":
            if len(args) != 2:
                raise ValueError("Uso: contacts remove <utilizador>")
            removed = self.profile.remove_contact(args[1])
            if removed:
                self.profile.save()
                self.session.request(
                    {
                        "type": "set_contacts_blob",
                        "contacts_blob": self.profile.export_contacts_blob(),
                    }
                )
                print("Contacto removido.")
            else:
                print("Contacto inexistente.")
            return True

        raise ValueError("Subcomando de contactos desconhecido.")

    def _fetch_user_certificate(self, username):
        response = self.session.request({"type": "get_user_certificate", "username": username})
        if not response.get("ok"):
            raise ValueError(response["message"])
        identity = validate_certificate(
            response["certificate"],
            self.ca_certificate_pem,
            expected_common_name=username,
            require_encryption_key=True,
        )
        return response["certificate"], identity

    def _fetch_delivery_bundle(self, username):
        response = self.session.request({"type": "get_delivery_bundle", "username": username})
        if not response.get("ok"):
            raise ValueError(response["message"])

        identity = validate_certificate(
            response["certificate_pem"],
            self.ca_certificate_pem,
            expected_common_name=username,
            require_encryption_key=True,
        )
        verify_signed_prekey(
            username,
            response["signed_prekey"],
            b64d(identity.signing_public_key_b64),
        )
        return response, identity

    def _send_message(self, recipient, message):
        if not self.profile.certificate_pem:
            raise ValueError("Perfil ainda sem certificado. Corre primeiro o registo.")

        contact = self.profile.get_contact(recipient)
        if not contact:
            raise ValueError(
                "Destinatario nao fixado. Usa 'contacts add <utilizador>' primeiro."
            )

        bundle, identity = self._fetch_delivery_bundle(recipient)
        if contact.certificate_pem != bundle["certificate_pem"]:
            raise ValueError(
                "O certificado devolvido pelo servidor nao coincide com o contacto fixado."
            )

        sent_at = utc_now()
        envelope = encrypt_e2e_message(
            sender=self.profile.username,
            recipient=recipient,
            message_text=message,
            sender_signing_private_key=self.profile.signing_private_key,
            sender_certificate_pem=self.profile.certificate_pem,
            sender_identity_private_key=self.profile.encryption_private_key,
            recipient_signing_public_key_raw=b64d(identity.signing_public_key_b64),
            recipient_identity_public_key_raw=b64d(identity.encryption_public_key_b64),
            recipient_signed_prekey=bundle["signed_prekey"],
            recipient_one_time_prekey=bundle["one_time_prekey"],
            sent_at=sent_at,
        )
        response = self.session.request(
            {
                "type": "send_message",
                "recipient": recipient,
                "envelope": envelope,
            }
        )
        if not response.get("ok"):
            raise ValueError(response["message"])
        print(f"Mensagem enviada com id {response['message_id']}.")

    def _fetch_messages(self):
        response = self.session.request({"type": "fetch_messages"})
        messages = response.get("messages", [])
        if not messages:
            print("Sem mensagens pendentes.")
            return

        ack_ids = []
        for item in messages:
            envelope = item["envelope"]
            if envelope.get("recipient") != self.profile.username:
                raise ValueError("Envelope inconsistente: recipient nao coincide com o perfil.")
            if envelope.get("sender") != item["sender"]:
                raise ValueError("Envelope inconsistente: sender nao coincide com o remetente.")

            sender = envelope["sender"]
            sender_contact = self.profile.get_contact(sender)
            payload, sender_identity = decrypt_e2e_message(
                envelope,
                self.profile.encryption_private_key,
                self.profile.get_signed_prekey_private(envelope["recipient_signed_prekey_id"]),
                self.profile.get_one_time_prekey_private(envelope["recipient_one_time_prekey_id"]),
                self.ca_certificate_pem,
            )

            if sender_contact and sender_contact.certificate_pem != sender_identity.certificate_pem:
                raise ValueError("O certificado do remetente nao coincide com o contacto fixado.")

            self.profile.remove_one_time_prekey(envelope["recipient_one_time_prekey_id"])
            trust_label = "verificado" if sender_contact else "nao fixado"
            print(
                f"[{item['id']}] {sender} -> {self.profile.username} "
                f"({envelope['sent_at']}, {trust_label}): {payload['message']}"
            )
            ack_ids.append(item["id"])

        self.profile.maybe_top_up_prekeys()
        self.profile.save()
        if ack_ids:
            ack_response = self.session.request({"type": "ack_messages", "ids": ack_ids})
            print(f"Mensagens confirmadas: {ack_response['acked']}")


def build_parser():
    parser = argparse.ArgumentParser(description="Cliente do chat seguro.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Cria um perfil local.")
    init_parser.add_argument("--username", required=True)
    init_parser.add_argument("--profile", required=True)

    for name in ("register", "shell"):
        sub = subparsers.add_parser(name, help=f"Executa '{name}'")
        sub.add_argument("--profile", required=True)
        sub.add_argument("--host", default="127.0.0.1")
        sub.add_argument("--port", type=int, default=9000)
        sub.add_argument("--ca-cert", required=True)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "init":
        password = read_password(confirm=True)
        profile = create_profile(args.profile, args.username, password)
        print(f"Perfil criado em {profile.path}")
        print(
            "Fingerprint assinatura="
            f"{fingerprint(b64d(profile.signing_public_key_b64))}, "
            f"enc={fingerprint(b64d(profile.encryption_public_key_b64))}"
        )
        return

    password = read_password(confirm=False)
    profile = load_profile(args.profile, password)
    ca_certificate_pem = load_ca_certificate(args.ca_cert)
    session = ClientSession(args.host, args.port, profile, ca_certificate_pem)

    try:
        if args.command == "register":
            response = session.register()
            print(response["message"])
            return

        if args.command == "shell":
            session.login()
            shell = ClientShell(session)
            shell.run()
            session.close()
            return
    finally:
        if session.sock is not None:
            try:
                session.close()
            except Exception:
                pass
