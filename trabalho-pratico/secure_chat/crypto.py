import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID, ObjectIdentifier

from .utils import b64d, b64e, canonical_json

PBKDF2_ITERATIONS = 390000
PBKDF2_SALT_SIZE = 16
AESGCM_NONCE_SIZE = 12
PROFILE_KEY_SIZE = 32
CONTACTS_KEY_SIZE = 32
SESSION_KEY_SIZE = 32
HKDF_HASH = hashes.SHA256()
SERVER_CERT_COMMON_NAME = "secure-chat-server"
ROOT_CA_COMMON_NAME = "SSI Secure Chat Root CA"
USER_ENCRYPTION_KEY_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
MESSAGE_SCHEME = "x3dh-otk-aesgcm-v1"


@dataclass
class CertificateIdentity:
    common_name: str
    certificate_pem: str
    signing_public_key_b64: str
    encryption_public_key_b64: Optional[str]
    certificate_fingerprint: str


def generate_ed25519_private_key():
    return ed25519.Ed25519PrivateKey.generate()


def generate_x25519_private_key():
    return x25519.X25519PrivateKey.generate()


def serialize_ed25519_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_ed25519_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def serialize_x25519_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_x25519_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_ed25519_private_key(raw):
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def load_ed25519_public_key(raw):
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def load_x25519_private_key(raw):
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def load_x25519_public_key(raw):
    return x25519.X25519PublicKey.from_public_bytes(raw)


def fingerprint(raw_public_key):
    return hashlib.sha256(raw_public_key).hexdigest()[:16]


def certificate_fingerprint(certificate_pem):
    return hashlib.sha256(certificate_pem.encode("utf-8")).hexdigest()[:16]


def derive_password_key(password, salt, length=PROFILE_KEY_SIZE):
    kdf = PBKDF2HMAC(
        algorithm=HKDF_HASH,
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)


def encrypt_with_aesgcm(key, plaintext, aad=None):
    nonce = os.urandom(AESGCM_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def decrypt_with_aesgcm(key, blob, aad=None):
    nonce = b64d(blob["nonce"])
    ciphertext = b64d(blob["ciphertext"])
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def hkdf_derive(secret, info, length):
    hkdf = HKDF(
        algorithm=HKDF_HASH,
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(secret)


def build_server_signature_payload(client_hello, server_hello_unsigned):
    return canonical_json(
        {
            "client_hello": client_hello,
            "server_hello": server_hello_unsigned,
        }
    )


def sign_payload(private_key, payload):
    return private_key.sign(payload)


def verify_signature(public_key, signature, payload):
    public_key.verify(signature, payload)


def build_session_keys(shared_secret, client_hello, server_hello_unsigned, is_client):
    transcript = build_server_signature_payload(client_hello, server_hello_unsigned)
    material = hkdf_derive(
        shared_secret,
        b"ssi-secure-chat-session:" + hashlib.sha256(transcript).digest(),
        72,
    )

    c2s_key = material[:SESSION_KEY_SIZE]
    s2c_key = material[SESSION_KEY_SIZE : 2 * SESSION_KEY_SIZE]
    c2s_prefix = material[64:68]
    s2c_prefix = material[68:72]

    if is_client:
        return {
            "send_key": c2s_key,
            "recv_key": s2c_key,
            "send_prefix": c2s_prefix,
            "recv_prefix": s2c_prefix,
        }

    return {
        "send_key": s2c_key,
        "recv_key": c2s_key,
        "send_prefix": s2c_prefix,
        "recv_prefix": c2s_prefix,
    }


def encrypt_contacts_blob(contacts_key, contacts):
    payload = canonical_json({"contacts": contacts})
    return encrypt_with_aesgcm(contacts_key, payload)


def decrypt_contacts_blob(contacts_key, blob):
    payload = decrypt_with_aesgcm(contacts_key, blob)
    return canonical_json_to_object(payload)


def canonical_json_to_object(data):
    import json

    return json.loads(data.decode("utf-8"))


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _utcnow():
    return datetime.now(timezone.utc)


def _not_valid_before(cert):
    value = getattr(cert, "not_valid_before_utc", None)
    if value is not None:
        return value
    return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _not_valid_after(cert):
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def serialize_certificate_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def load_certificate(certificate_pem):
    return x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))


def create_root_ca(common_name=ROOT_CA_COMMON_NAME):
    private_key = generate_ed25519_private_key()
    now = _utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, algorithm=None)
    )
    return private_key, serialize_certificate_pem(certificate)


def issue_leaf_certificate(
    ca_private_key,
    ca_certificate_pem,
    common_name,
    subject_public_key,
    identity_encryption_public_key_raw=None,
):
    ca_certificate = load_certificate(ca_certificate_pem)
    now = _utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_certificate.subject)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    if identity_encryption_public_key_raw is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                USER_ENCRYPTION_KEY_OID,
                identity_encryption_public_key_raw,
            ),
            critical=False,
        )

    certificate = builder.sign(ca_private_key, algorithm=None)
    return serialize_certificate_pem(certificate)


def extract_certificate_identity(certificate_pem, require_encryption_key=True):
    certificate = load_certificate(certificate_pem)
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names:
        raise ValueError("Certificado sem Common Name.")

    encryption_public_key_b64 = None
    if require_encryption_key:
        try:
            extension = certificate.extensions.get_extension_for_oid(USER_ENCRYPTION_KEY_OID)
        except x509.ExtensionNotFound as exc:
            raise ValueError("Certificado sem chave X25519 de identidade.") from exc
        encryption_public_key_raw = extension.value.value
        if len(encryption_public_key_raw) != 32:
            raise ValueError("Certificado com chave X25519 invalida.")
        encryption_public_key_b64 = b64e(encryption_public_key_raw)

    signing_public_key = certificate.public_key()
    if not isinstance(signing_public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Certificado com chave publica de assinatura nao suportada.")

    return CertificateIdentity(
        common_name=names[0].value,
        certificate_pem=certificate_pem,
        signing_public_key_b64=b64e(serialize_ed25519_public_key(signing_public_key)),
        encryption_public_key_b64=encryption_public_key_b64,
        certificate_fingerprint=certificate_fingerprint(certificate_pem),
    )


def validate_certificate(
    certificate_pem,
    ca_certificate_pem,
    expected_common_name=None,
    require_encryption_key=True,
):
    certificate = load_certificate(certificate_pem)
    ca_certificate = load_certificate(ca_certificate_pem)
    if certificate.issuer != ca_certificate.subject:
        raise ValueError("Emissor do certificado nao corresponde a CA confiada.")

    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, ed25519.Ed25519PublicKey):
        raise ValueError("CA com algoritmo de assinatura nao suportado.")
    ca_public_key.verify(certificate.signature, certificate.tbs_certificate_bytes)

    now = _utcnow()
    if now < _not_valid_before(certificate) or now > _not_valid_after(certificate):
        raise ValueError("Certificado fora do periodo de validade.")

    identity = extract_certificate_identity(
        certificate_pem,
        require_encryption_key=require_encryption_key,
    )
    if expected_common_name and identity.common_name != expected_common_name:
        raise ValueError("Common Name do certificado nao coincide com a identidade esperada.")
    return identity


def build_registration_proof_payload(username, signing_public_key_b64, encryption_public_key_b64):
    return canonical_json(
        {
            "username": username,
            "signing_public_key": signing_public_key_b64,
            "encryption_public_key": encryption_public_key_b64,
        }
    )


def build_signed_prekey_payload(username, key_id, public_key_b64, created_at):
    return canonical_json(
        {
            "username": username,
            "key_id": key_id,
            "public_key": public_key_b64,
            "created_at": created_at,
        }
    )


def sign_signed_prekey(signing_private_key, username, key_id, public_key_b64, created_at):
    payload = build_signed_prekey_payload(username, key_id, public_key_b64, created_at)
    return b64e(sign_payload(signing_private_key, payload))


def verify_signed_prekey(username, signed_prekey, signing_public_key_raw):
    required = {"key_id", "public_key", "created_at", "signature"}
    if not required.issubset(signed_prekey):
        raise ValueError("Signed prekey incompleta.")

    verify_signature(
        load_ed25519_public_key(signing_public_key_raw),
        b64d(signed_prekey["signature"]),
        build_signed_prekey_payload(
            username,
            signed_prekey["key_id"],
            signed_prekey["public_key"],
            signed_prekey["created_at"],
        ),
    )

    load_x25519_public_key(b64d(signed_prekey["public_key"]))


def build_e2e_aad(sender, recipient, sent_at, recipient_signed_prekey_id, recipient_one_time_prekey_id):
    return {
        "version": 2,
        "scheme": MESSAGE_SCHEME,
        "sender": sender,
        "recipient": recipient,
        "sent_at": sent_at,
        "recipient_signed_prekey_id": recipient_signed_prekey_id,
        "recipient_one_time_prekey_id": recipient_one_time_prekey_id,
    }


def build_e2e_signature_payload(
    aad,
    sender_certificate_pem,
    sender_ephemeral_public_key_b64,
    nonce_b64,
    ciphertext_b64,
):
    return canonical_json(
        {
            "aad": aad,
            "sender_certificate": sender_certificate_pem,
            "sender_ephemeral_public_key": sender_ephemeral_public_key_b64,
            "nonce": nonce_b64,
            "ciphertext": ciphertext_b64,
        }
    )


def _derive_x3dh_material_sender(
    sender_identity_private_key,
    sender_ephemeral_private_key,
    recipient_identity_public_key_raw,
    recipient_signed_prekey_public_key_raw,
    recipient_one_time_prekey_public_key_raw,
):
    recipient_identity_public_key = load_x25519_public_key(recipient_identity_public_key_raw)
    recipient_signed_prekey_public_key = load_x25519_public_key(
        recipient_signed_prekey_public_key_raw
    )
    recipient_one_time_prekey_public_key = load_x25519_public_key(
        recipient_one_time_prekey_public_key_raw
    )

    dh1 = sender_identity_private_key.exchange(recipient_signed_prekey_public_key)
    dh2 = sender_ephemeral_private_key.exchange(recipient_identity_public_key)
    dh3 = sender_ephemeral_private_key.exchange(recipient_signed_prekey_public_key)
    dh4 = sender_ephemeral_private_key.exchange(recipient_one_time_prekey_public_key)
    return dh1 + dh2 + dh3 + dh4


def _derive_x3dh_material_recipient(
    recipient_identity_private_key,
    recipient_signed_prekey_private_key,
    recipient_one_time_prekey_private_key,
    sender_identity_public_key_raw,
    sender_ephemeral_public_key_raw,
):
    if recipient_one_time_prekey_private_key is None:
        raise ValueError("One-time prekey ja nao esta disponivel para esta mensagem.")

    sender_identity_public_key = load_x25519_public_key(sender_identity_public_key_raw)
    sender_ephemeral_public_key = load_x25519_public_key(sender_ephemeral_public_key_raw)

    dh1 = recipient_signed_prekey_private_key.exchange(sender_identity_public_key)
    dh2 = recipient_identity_private_key.exchange(sender_ephemeral_public_key)
    dh3 = recipient_signed_prekey_private_key.exchange(sender_ephemeral_public_key)
    dh4 = recipient_one_time_prekey_private_key.exchange(sender_ephemeral_public_key)
    return dh1 + dh2 + dh3 + dh4


def _derive_message_key(secret_material, aad):
    return hkdf_derive(
        secret_material,
        b"ssi-e2e-message:" + hashlib.sha256(canonical_json(aad)).digest(),
        SESSION_KEY_SIZE,
    )


def encrypt_e2e_message(
    sender,
    recipient,
    message_text,
    sender_signing_private_key,
    sender_certificate_pem,
    sender_identity_private_key,
    recipient_signing_public_key_raw,
    recipient_identity_public_key_raw,
    recipient_signed_prekey,
    recipient_one_time_prekey,
    sent_at,
):
    verify_signed_prekey(recipient, recipient_signed_prekey, recipient_signing_public_key_raw)

    recipient_signed_prekey_public_key_raw = b64d(recipient_signed_prekey["public_key"])
    recipient_one_time_prekey_public_key_raw = b64d(recipient_one_time_prekey["public_key"])
    sender_ephemeral_private_key = generate_x25519_private_key()
    sender_ephemeral_public_key_b64 = b64e(
        serialize_x25519_public_key(sender_ephemeral_private_key.public_key())
    )

    aad = build_e2e_aad(
        sender,
        recipient,
        sent_at,
        recipient_signed_prekey["key_id"],
        recipient_one_time_prekey["key_id"],
    )
    secret_material = _derive_x3dh_material_sender(
        sender_identity_private_key,
        sender_ephemeral_private_key,
        recipient_identity_public_key_raw,
        recipient_signed_prekey_public_key_raw,
        recipient_one_time_prekey_public_key_raw,
    )
    key = _derive_message_key(secret_material, aad)
    blob = encrypt_with_aesgcm(
        key,
        canonical_json({"message": message_text}),
        canonical_json(aad),
    )
    signature_payload = build_e2e_signature_payload(
        aad,
        sender_certificate_pem,
        sender_ephemeral_public_key_b64,
        blob["nonce"],
        blob["ciphertext"],
    )
    signature = sign_payload(sender_signing_private_key, signature_payload)

    return {
        **aad,
        "sender_certificate": sender_certificate_pem,
        "sender_ephemeral_public_key": sender_ephemeral_public_key_b64,
        "nonce": blob["nonce"],
        "ciphertext": blob["ciphertext"],
        "signature": b64e(signature),
    }


def decrypt_e2e_message(
    envelope,
    recipient_identity_private_key,
    recipient_signed_prekey_private_key,
    recipient_one_time_prekey_private_key,
    ca_certificate_pem,
):
    aad = build_e2e_aad(
        envelope["sender"],
        envelope["recipient"],
        envelope["sent_at"],
        envelope["recipient_signed_prekey_id"],
        envelope["recipient_one_time_prekey_id"],
    )
    if aad["version"] != envelope.get("version") or aad["scheme"] != envelope.get("scheme"):
        raise ValueError("Envelope E2EE com metadata inconsistente.")

    sender_identity = validate_certificate(
        envelope["sender_certificate"],
        ca_certificate_pem,
        expected_common_name=envelope["sender"],
        require_encryption_key=True,
    )
    signature_payload = build_e2e_signature_payload(
        aad,
        envelope["sender_certificate"],
        envelope["sender_ephemeral_public_key"],
        envelope["nonce"],
        envelope["ciphertext"],
    )
    verify_signature(
        load_ed25519_public_key(b64d(sender_identity.signing_public_key_b64)),
        b64d(envelope["signature"]),
        signature_payload,
    )

    secret_material = _derive_x3dh_material_recipient(
        recipient_identity_private_key,
        recipient_signed_prekey_private_key,
        recipient_one_time_prekey_private_key,
        b64d(sender_identity.encryption_public_key_b64),
        b64d(envelope["sender_ephemeral_public_key"]),
    )
    key = _derive_message_key(secret_material, aad)
    plaintext = AESGCM(key).decrypt(
        b64d(envelope["nonce"]),
        b64d(envelope["ciphertext"]),
        canonical_json(aad),
    )
    return canonical_json_to_object(plaintext), sender_identity
