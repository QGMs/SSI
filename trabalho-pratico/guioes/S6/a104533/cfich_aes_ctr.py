#!/usr/bin/env python3
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_SIZE = 32
IV_SIZE = 16


def read_key(path: str) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError("invalid AES key size")
    return key


def aes_ctr_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    worker = cipher.encryptor()
    return worker.update(data) + worker.finalize()


def cmd_setup(fkey: str) -> None:
    Path(fkey).write_bytes(os.urandom(KEY_SIZE))


def cmd_enc(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    iv = os.urandom(IV_SIZE)
    ptxt = Path(fich).read_bytes()
    ctxt = aes_ctr_crypt(ptxt, key, iv)
    Path(f"{fich}.enc").write_bytes(iv + ctxt)


def cmd_dec(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    blob = Path(fich).read_bytes()
    if len(blob) < IV_SIZE:
        raise ValueError("ciphertext file too short")
    iv = blob[:IV_SIZE]
    ctxt = blob[IV_SIZE:]
    ptxt = aes_ctr_crypt(ctxt, key, iv)
    Path(f"{fich}.dec").write_bytes(ptxt)


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage:", file=sys.stderr)
        print("  python3 cfich_aes_ctr.py setup <fkey>", file=sys.stderr)
        print("  python3 cfich_aes_ctr.py enc <fich> <fkey>", file=sys.stderr)
        print("  python3 cfich_aes_ctr.py dec <fich> <fkey>", file=sys.stderr)
        return 1

    cmd = sys.argv[1]
    if cmd == "setup" and len(sys.argv) == 3:
        cmd_setup(sys.argv[2])
        return 0
    if cmd == "enc" and len(sys.argv) == 4:
        cmd_enc(sys.argv[2], sys.argv[3])
        return 0
    if cmd == "dec" and len(sys.argv) == 4:
        cmd_dec(sys.argv[2], sys.argv[3])
        return 0

    print("invalid arguments", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
