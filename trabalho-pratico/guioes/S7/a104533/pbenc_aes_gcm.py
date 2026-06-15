#!/usr/bin/env python3
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITER = 200000


def read_passphrase() -> bytes:
    data = sys.stdin.buffer.readline()
    if not data:
        raise ValueError("missing passphrase on stdin")
    return data.rstrip(b"\r\n")


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive(passphrase)


def cmd_enc(fich: str) -> None:
    passphrase = read_passphrase()
    salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(NONCE_SIZE)
    ptxt = Path(fich).read_bytes()
    # Authenticate the salt as associated data without storing it twice.
    ctxt = AESGCM(key).encrypt(nonce, ptxt, salt)
    Path(f"{fich}.enc").write_bytes(salt + nonce + ctxt)


def cmd_dec(fich: str) -> None:
    passphrase = read_passphrase()
    blob = Path(fich).read_bytes()
    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("ciphertext file too short")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ctxt = blob[SALT_SIZE + NONCE_SIZE :]
    key = derive_key(passphrase, salt)
    ptxt = AESGCM(key).decrypt(nonce, ctxt, salt)
    Path(f"{fich}.dec").write_bytes(ptxt)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage:", file=sys.stderr)
        print("  printf 'pass\\n' | python3 pbenc_aes_gcm.py enc <fich>", file=sys.stderr)
        print("  printf 'pass\\n' | python3 pbenc_aes_gcm.py dec <fich>", file=sys.stderr)
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
