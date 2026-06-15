import json
import os
from dataclasses import dataclass
from pathlib import Path

from .crypto import (
    CONTACTS_KEY_SIZE,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_SIZE,
    decrypt_contacts_blob,
    decrypt_with_aesgcm,
    derive_password_key,
    encrypt_contacts_blob,
    encrypt_with_aesgcm,
    generate_ed25519_private_key,
    generate_x25519_private_key,
    load_ed25519_private_key,
    load_x25519_private_key,
    serialize_ed25519_private_key,
    serialize_ed25519_public_key,
    serialize_x25519_private_key,
    serialize_x25519_public_key,
    sign_signed_prekey,
)
from .utils import b64d, b64e, ensure_parent_dir, utc_now

DEFAULT_PREKEY_TARGET = 12
DEFAULT_PREKEY_MINIMUM = 6


@dataclass
class ContactEntry:
    username: str
    certificate_pem: str
    added_at: str

    def to_dict(self):
        return {
            "username": self.username,
            "certificate_pem": self.certificate_pem,
            "added_at": self.added_at,
        }


@dataclass
class SignedPrekeyEntry:
    key_id: str
    private_key: object
    created_at: str
    signature: str

    @property
    def public_key_b64(self):
        return b64e(serialize_x25519_public_key(self.private_key.public_key()))

    def to_public_record(self):
        return {
            "key_id": self.key_id,
            "public_key": self.public_key_b64,
            "created_at": self.created_at,
            "signature": self.signature,
        }

    def to_private_record(self):
        return {
            "key_id": self.key_id,
            "private_key": b64e(serialize_x25519_private_key(self.private_key)),
            "created_at": self.created_at,
            "signature": self.signature,
        }


@dataclass
class OneTimePrekeyEntry:
    key_id: str
    private_key: object
    created_at: str
    uploaded_at: str | None

    @property
    def public_key_b64(self):
        return b64e(serialize_x25519_public_key(self.private_key.public_key()))

    def to_public_record(self):
        return {
            "key_id": self.key_id,
            "public_key": self.public_key_b64,
            "created_at": self.created_at,
        }

    def to_private_record(self):
        return {
            "key_id": self.key_id,
            "private_key": b64e(serialize_x25519_private_key(self.private_key)),
            "created_at": self.created_at,
            "uploaded_at": self.uploaded_at,
        }


class UnlockedProfile:
    def __init__(
        self,
        path,
        username,
        salt,
        master_key,
        signing_private_key,
        encryption_private_key,
        contacts_key,
        contacts,
        certificate_pem,
        signed_prekeys,
        active_signed_prekey_id,
        one_time_prekeys,
        created_at,
        updated_at,
    ):
        self.path = Path(path).expanduser().resolve()
        self.username = username
        self.salt = salt
        self.master_key = master_key
        self.signing_private_key = signing_private_key
        self.encryption_private_key = encryption_private_key
        self.contacts_key = contacts_key
        self.contacts = contacts
        self.certificate_pem = certificate_pem
        self.signed_prekeys = signed_prekeys
        self.active_signed_prekey_id = active_signed_prekey_id
        self.one_time_prekeys = one_time_prekeys
        self.created_at = created_at
        self.updated_at = updated_at

    @property
    def signing_public_key_b64(self):
        return b64e(serialize_ed25519_public_key(self.signing_private_key.public_key()))

    @property
    def encryption_public_key_b64(self):
        return b64e(serialize_x25519_public_key(self.encryption_private_key.public_key()))

    def list_contacts(self):
        return [self.contacts[name].to_dict() for name in sorted(self.contacts)]

    def get_contact(self, username):
        return self.contacts.get(username)

    def upsert_contact(self, username, certificate_pem):
        existing = self.contacts.get(username)
        if existing:
            if existing.certificate_pem != certificate_pem:
                raise ValueError(
                    "O certificado do contacto mudou. Operacao bloqueada para evitar impersonacao."
                )
            return existing

        entry = ContactEntry(
            username=username,
            certificate_pem=certificate_pem,
            added_at=utc_now(),
        )
        self.contacts[username] = entry
        self.updated_at = utc_now()
        return entry

    def remove_contact(self, username):
        removed = self.contacts.pop(username, None)
        if removed is not None:
            self.updated_at = utc_now()
        return removed

    def export_contacts_blob(self):
        return encrypt_contacts_blob(self.contacts_key, self.list_contacts())

    def merge_remote_contacts_blob(self, blob):
        if not blob:
            return

        remote_payload = decrypt_contacts_blob(self.contacts_key, blob)
        for entry in remote_payload.get("contacts", []):
            certificate_pem = entry.get("certificate_pem")
            if not certificate_pem:
                continue
            self.upsert_contact(entry["username"], certificate_pem)

    def set_certificate(self, certificate_pem):
        if self.certificate_pem and self.certificate_pem != certificate_pem:
            raise ValueError("O certificado local ja existe e nao coincide com o emitido.")
        self.certificate_pem = certificate_pem
        self.updated_at = utc_now()

    def _generate_key_id(self, prefix):
        return f"{prefix}-{int.from_bytes(os.urandom(6), 'big'):012x}"

    def _create_signed_prekey(self):
        key_id = self._generate_key_id("spk")
        private_key = generate_x25519_private_key()
        created_at = utc_now()
        signature = sign_signed_prekey(
            self.signing_private_key,
            self.username,
            key_id,
            b64e(serialize_x25519_public_key(private_key.public_key())),
            created_at,
        )
        entry = SignedPrekeyEntry(
            key_id=key_id,
            private_key=private_key,
            created_at=created_at,
            signature=signature,
        )
        self.signed_prekeys[key_id] = entry
        self.active_signed_prekey_id = key_id
        self.updated_at = utc_now()
        return entry

    def _create_one_time_prekey(self):
        key_id = self._generate_key_id("otk")
        entry = OneTimePrekeyEntry(
            key_id=key_id,
            private_key=generate_x25519_private_key(),
            created_at=utc_now(),
            uploaded_at=None,
        )
        self.one_time_prekeys[key_id] = entry
        self.updated_at = utc_now()
        return entry

    def ensure_prekeys(self, target=DEFAULT_PREKEY_TARGET):
        if not self.active_signed_prekey_id or self.active_signed_prekey_id not in self.signed_prekeys:
            self._create_signed_prekey()

        missing = max(0, target - len(self.one_time_prekeys))
        for _ in range(missing):
            self._create_one_time_prekey()

    def build_prekey_upload(self, target=DEFAULT_PREKEY_TARGET):
        self.ensure_prekeys(target=target)
        active_signed_prekey = self.signed_prekeys[self.active_signed_prekey_id]
        unpublished_one_time_prekeys = [
            entry.to_public_record()
            for entry in self.one_time_prekeys.values()
            if entry.uploaded_at is None
        ]
        return {
            "signed_prekey": active_signed_prekey.to_public_record(),
            "one_time_prekeys": unpublished_one_time_prekeys,
        }

    def mark_prekeys_uploaded(self, key_ids):
        timestamp = utc_now()
        for key_id in key_ids:
            entry = self.one_time_prekeys.get(key_id)
            if entry is not None and entry.uploaded_at is None:
                entry.uploaded_at = timestamp
        self.updated_at = utc_now()

    def maybe_top_up_prekeys(self, minimum=DEFAULT_PREKEY_MINIMUM, target=DEFAULT_PREKEY_TARGET):
        if len(self.one_time_prekeys) < minimum:
            self.ensure_prekeys(target=target)

    def get_signed_prekey_private(self, key_id):
        entry = self.signed_prekeys.get(key_id)
        if entry is None:
            raise ValueError("Signed prekey necessaria nao encontrada no perfil.")
        return entry.private_key

    def get_one_time_prekey_private(self, key_id):
        entry = self.one_time_prekeys.get(key_id)
        if entry is None:
            return None
        return entry.private_key

    def remove_one_time_prekey(self, key_id):
        removed = self.one_time_prekeys.pop(key_id, None)
        if removed is not None:
            self.updated_at = utc_now()
        return removed

    def save(self):
        ensure_parent_dir(self.path)
        private_payload = {
            "signing_private_key": b64e(serialize_ed25519_private_key(self.signing_private_key)),
            "encryption_private_key": b64e(
                serialize_x25519_private_key(self.encryption_private_key)
            ),
            "contacts_key": b64e(self.contacts_key),
            "contacts": self.list_contacts(),
            "signed_prekeys": [
                self.signed_prekeys[key_id].to_private_record()
                for key_id in sorted(self.signed_prekeys)
            ],
            "active_signed_prekey_id": self.active_signed_prekey_id,
            "one_time_prekeys": [
                self.one_time_prekeys[key_id].to_private_record()
                for key_id in sorted(self.one_time_prekeys)
            ],
        }
        private_blob = encrypt_with_aesgcm(
            self.master_key,
            json.dumps(private_payload, sort_keys=True).encode("utf-8"),
        )
        file_data = {
            "version": 2,
            "username": self.username,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "kdf": {
                "iterations": PBKDF2_ITERATIONS,
                "salt": b64e(self.salt),
            },
            "public_keys": {
                "signing": self.signing_public_key_b64,
                "encryption": self.encryption_public_key_b64,
            },
            "certificate_pem": self.certificate_pem,
            "private_blob": private_blob,
        }
        self.path.write_text(json.dumps(file_data, indent=2), encoding="utf-8")


def create_profile(path, username, password):
    signing_private_key = generate_ed25519_private_key()
    encryption_private_key = generate_x25519_private_key()
    salt = os.urandom(PBKDF2_SALT_SIZE)
    master_key = derive_password_key(password, salt)
    contacts_key = os.urandom(CONTACTS_KEY_SIZE)
    now = utc_now()

    profile = UnlockedProfile(
        path=path,
        username=username,
        salt=salt,
        master_key=master_key,
        signing_private_key=signing_private_key,
        encryption_private_key=encryption_private_key,
        contacts_key=contacts_key,
        contacts={},
        certificate_pem=None,
        signed_prekeys={},
        active_signed_prekey_id=None,
        one_time_prekeys={},
        created_at=now,
        updated_at=now,
    )
    profile.ensure_prekeys()
    profile.save()
    return profile


def load_profile(path, password):
    file_path = Path(path).expanduser().resolve()
    data = json.loads(file_path.read_text(encoding="utf-8"))
    salt = b64d(data["kdf"]["salt"])
    master_key = derive_password_key(password, salt)
    private_payload = json.loads(
        decrypt_with_aesgcm(master_key, data["private_blob"]).decode("utf-8")
    )

    contacts = {}
    for item in private_payload.get("contacts", []):
        certificate_pem = item.get("certificate_pem")
        if not certificate_pem:
            continue
        contacts[item["username"]] = ContactEntry(
            username=item["username"],
            certificate_pem=certificate_pem,
            added_at=item["added_at"],
        )

    signed_prekeys = {}
    for item in private_payload.get("signed_prekeys", []):
        signed_prekeys[item["key_id"]] = SignedPrekeyEntry(
            key_id=item["key_id"],
            private_key=load_x25519_private_key(b64d(item["private_key"])),
            created_at=item["created_at"],
            signature=item["signature"],
        )

    one_time_prekeys = {}
    for item in private_payload.get("one_time_prekeys", []):
        one_time_prekeys[item["key_id"]] = OneTimePrekeyEntry(
            key_id=item["key_id"],
            private_key=load_x25519_private_key(b64d(item["private_key"])),
            created_at=item["created_at"],
            uploaded_at=item.get("uploaded_at"),
        )

    profile = UnlockedProfile(
        path=file_path,
        username=data["username"],
        salt=salt,
        master_key=master_key,
        signing_private_key=load_ed25519_private_key(
            b64d(private_payload["signing_private_key"])
        ),
        encryption_private_key=load_x25519_private_key(
            b64d(private_payload["encryption_private_key"])
        ),
        contacts_key=b64d(private_payload["contacts_key"]),
        contacts=contacts,
        certificate_pem=data.get("certificate_pem"),
        signed_prekeys=signed_prekeys,
        active_signed_prekey_id=private_payload.get("active_signed_prekey_id"),
        one_time_prekeys=one_time_prekeys,
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )
    profile.maybe_top_up_prekeys()
    return profile
