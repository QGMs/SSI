#!/usr/bin/env python3
import os
from multiprocessing import Pipe, Process
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID


P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B
80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22
514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D
F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6
F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB
5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
9ED52907 7096966D 670C354E 4ABC9804 F1746C08
CA18217C 32905E46 2E36CE3B E39E772C 180E8603
9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6
95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""
G = 2
NONCE_SIZE = 12
AES_KEY_SIZE = 32
REQUIRED_FILES = ("CA.crt", "Alice.key", "Alice.crt", "Bob.key", "Bob.crt")


def mkpair(x, y):
    len_x = len(x)
    if len_x > 65535:
        raise ValueError("first component too large for mkpair")
    return len_x.to_bytes(2, "little") + x + y


def unpair(xy):
    if len(xy) < 2:
        raise ValueError("pair too short")
    len_x = int.from_bytes(xy[:2], "little")
    if len(xy) < len_x + 2:
        raise ValueError("pair truncated")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y


def build_parameters():
    p = int("".join(P_HEX.split()), 16)
    return dh.DHParameterNumbers(p, G).parameters()


def serialize_dh_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_dh_public_key(data):
    return serialization.load_der_public_key(data)


def load_pem_private_key(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_cert(path):
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b"sts aes gcm key",
    )
    return hkdf.derive(shared_secret)


def encrypt_message(key, plaintext):
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def decrypt_message(key, blob):
    if len(blob) < NONCE_SIZE + 16:
        raise ValueError("ciphertext too short")
    nonce = blob[:NONCE_SIZE]
    ctxt = blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ctxt, None)


def verify_certificate(cert_bytes, ca_cert, expected_cn):
    cert = x509.load_pem_x509_certificate(cert_bytes)
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    if cert.issuer != ca_cert.subject:
        raise ValueError("certificate issuer does not match CA")
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or names[0].value != expected_cn:
        raise ValueError(f"unexpected certificate subject for {expected_cn}")
    return cert


def sign_transcript(private_key, first, second):
    data = mkpair(first, second)
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_transcript_signature(public_key, signature, first, second):
    data = mkpair(first, second)
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def alice_process(conn):
    ca_cert = load_cert("CA.crt")
    alice_sign_key = load_pem_private_key("Alice.key")
    alice_cert_bytes = Path("Alice.crt").read_bytes()

    dh_private_key = build_parameters().generate_private_key()
    alice_dh_bytes = serialize_dh_public_key(dh_private_key.public_key())

    conn.send(alice_dh_bytes)

    bob_packet = conn.recv()
    bob_dh_bytes, bob_rest = unpair(bob_packet)
    bob_signature, bob_cert_bytes = unpair(bob_rest)

    bob_cert = verify_certificate(bob_cert_bytes, ca_cert, "Bob")
    verify_transcript_signature(
        bob_cert.public_key(),
        bob_signature,
        bob_dh_bytes,
        alice_dh_bytes,
    )

    bob_dh_public_key = load_dh_public_key(bob_dh_bytes)
    shared_secret = dh_private_key.exchange(bob_dh_public_key)
    print(f"Alice K: {shared_secret.hex()}", flush=True)

    alice_signature = sign_transcript(alice_sign_key, alice_dh_bytes, bob_dh_bytes)
    conn.send(mkpair(alice_signature, alice_cert_bytes))

    aes_key = derive_aes_key(shared_secret)
    conn.send(encrypt_message(aes_key, b"Ola Bob, mensagem protegida por STS."))

    reply = decrypt_message(aes_key, conn.recv())
    print(f"Alice recebeu: {reply.decode('utf-8')}", flush=True)


def bob_process(conn):
    ca_cert = load_cert("CA.crt")
    bob_sign_key = load_pem_private_key("Bob.key")
    bob_cert_bytes = Path("Bob.crt").read_bytes()

    dh_private_key = build_parameters().generate_private_key()
    bob_dh_bytes = serialize_dh_public_key(dh_private_key.public_key())

    alice_dh_bytes = conn.recv()

    bob_signature = sign_transcript(bob_sign_key, bob_dh_bytes, alice_dh_bytes)
    conn.send(mkpair(bob_dh_bytes, mkpair(bob_signature, bob_cert_bytes)))

    alice_packet = conn.recv()
    alice_signature, alice_cert_bytes = unpair(alice_packet)

    alice_cert = verify_certificate(alice_cert_bytes, ca_cert, "Alice")
    verify_transcript_signature(
        alice_cert.public_key(),
        alice_signature,
        alice_dh_bytes,
        bob_dh_bytes,
    )

    alice_dh_public_key = load_dh_public_key(alice_dh_bytes)
    shared_secret = dh_private_key.exchange(alice_dh_public_key)
    print(f"Bob K:   {shared_secret.hex()}", flush=True)

    aes_key = derive_aes_key(shared_secret)
    msg = decrypt_message(aes_key, conn.recv())
    print(f"Bob recebeu: {msg.decode('utf-8')}", flush=True)

    conn.send(encrypt_message(aes_key, b"Ola Alice, assinatura e certificado validados."))


def main():
    missing = [name for name in REQUIRED_FILES if not Path(name).exists()]
    if missing:
        raise FileNotFoundError(
            "missing certificate material: "
            + ", ".join(missing)
            + " (run ./gen_certs.sh first)"
        )

    parent_conn, child_conn = Pipe()
    alice = Process(target=alice_process, args=(parent_conn,))
    bob = Process(target=bob_process, args=(child_conn,))
    alice.start()
    bob.start()
    alice.join()
    bob.join()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}")
        raise SystemExit(1)
