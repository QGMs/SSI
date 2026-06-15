#!/usr/bin/env python3
import hmac
import os
import sys
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ENC_KEY_SIZE = 32
MAC_KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 16
PBKDF2_ITER = 200000
TAG_SIZE = 32


def read_passphrase() -> bytes:
    data = sys.stdin.buffer.readline()
    if not data:
        raise ValueError("missing passphrase on stdin")
    return data.rstrip(b"\r\n")


def derive_keys(passphrase: bytes, salt: bytes) -> tuple[bytes, bytes]:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENC_KEY_SIZE + MAC_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    material = kdf.derive(passphrase)
    return material[:ENC_KEY_SIZE], material[ENC_KEY_SIZE:]


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    worker = cipher.encryptor()
    return worker.update(data) + worker.finalize()


def make_tag(mac_key: bytes, data: bytes) -> bytes:
    return hmac.new(mac_key, data, sha256).digest()


def cmd_enc(fich: str) -> None:
    passphrase = read_passphrase()
    salt = os.urandom(SALT_SIZE)
    enc_key, mac_key = derive_keys(passphrase, salt)
    nonce = os.urandom(NONCE_SIZE)
    ptxt = Path(fich).read_bytes()
    ctxt = aes_ctr_crypt(ptxt, enc_key, nonce)
    body = salt + nonce + ctxt
    tag = make_tag(mac_key, body)
    Path(f"{fich}.enc").write_bytes(body + tag)


def cmd_dec(fich: str) -> None:
    passphrase = read_passphrase()
    blob = Path(fich).read_bytes()
    min_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(blob) < min_len:
        raise ValueError("ciphertext file too short")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ctxt = blob[SALT_SIZE + NONCE_SIZE : -TAG_SIZE]
    tag = blob[-TAG_SIZE:]
    enc_key, mac_key = derive_keys(passphrase, salt)

    expected = make_tag(mac_key, blob[:-TAG_SIZE])
    if not hmac.compare_digest(expected, tag):
        raise ValueError("invalid MAC")

    ptxt = aes_ctr_crypt(ctxt, enc_key, nonce)
    Path(f"{fich}.dec").write_bytes(ptxt)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage:", file=sys.stderr)
        print("  printf 'pass\\n' | python3 pbenc_aes_ctr_hmac.py enc <fich>", file=sys.stderr)
        print("  printf 'pass\\n' | python3 pbenc_aes_ctr_hmac.py dec <fich>", file=sys.stderr)
        return 1

    cmd = sys.argv[1]
    if cmd == "enc":
        cmd_enc(sys.argv[2])
        return 0
    if cmd == "dec":
        cmd_dec(sys.argv[2])
        return 0

    print("invalid arguments", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
