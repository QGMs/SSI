#!/usr/bin/env python3
import os
from multiprocessing import Pipe, Process

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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


def build_parameters():
    p = int("".join(P_HEX.split()), 16)
    return dh.DHParameterNumbers(p, G).parameters()


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_peer_public_key(data):
    return serialization.load_der_public_key(data)


def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b"dh aes gcm key",
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


def alice_process(conn):
    private_key = build_parameters().generate_private_key()
    alice_pub_bytes = serialize_public_key(private_key.public_key())

    conn.send(alice_pub_bytes)
    bob_pub_bytes = conn.recv()

    bob_public_key = load_peer_public_key(bob_pub_bytes)
    shared_secret = private_key.exchange(bob_public_key)
    print(f"Alice K: {shared_secret.hex()}", flush=True)

    aes_key = derive_aes_key(shared_secret)
    conn.send(encrypt_message(aes_key, b"Ola Bob, mensagem secreta de Alice."))

    reply = decrypt_message(aes_key, conn.recv())
    print(f"Alice recebeu: {reply.decode('utf-8')}", flush=True)


def bob_process(conn):
    private_key = build_parameters().generate_private_key()
    bob_pub_bytes = serialize_public_key(private_key.public_key())

    alice_pub_bytes = conn.recv()
    conn.send(bob_pub_bytes)

    alice_public_key = load_peer_public_key(alice_pub_bytes)
    shared_secret = private_key.exchange(alice_public_key)
    print(f"Bob K:   {shared_secret.hex()}", flush=True)

    aes_key = derive_aes_key(shared_secret)
    msg = decrypt_message(aes_key, conn.recv())
    print(f"Bob recebeu: {msg.decode('utf-8')}", flush=True)

    conn.send(encrypt_message(aes_key, b"Ola Alice, mensagem secreta de Bob."))


def main():
    parent_conn, child_conn = Pipe()
    alice = Process(target=alice_process, args=(parent_conn,))
    bob = Process(target=bob_process, args=(child_conn,))
    alice.start()
    bob.start()
    alice.join()
    bob.join()


if __name__ == "__main__":
    main()
