#!/usr/bin/env python3
import hashlib
import hmac
import os
import sys
from pathlib import Path


KEY_SIZE = 32


def read_key(path: str) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError("invalid SHA256 MAC key size")
    return key


def prefix_mac(key: bytes, msg: bytes) -> str:
    return hashlib.sha256(key + msg).hexdigest()


def cmd_setup(fkey: str) -> None:
    Path(fkey).write_bytes(os.urandom(KEY_SIZE))


def cmd_mac(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    msg = Path(fich).read_bytes()
    Path(f"{fich}.mac").write_text(prefix_mac(key, msg), encoding="ascii")


def cmd_ver(fich: str, fkey: str) -> None:
    key = read_key(fkey)
    msg = Path(fich).read_bytes()
    expected = prefix_mac(key, msg)
    got = Path(f"{fich}.mac").read_text(encoding="ascii").strip()
    print(hmac.compare_digest(expected, got))


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage:", file=sys.stderr)
        print("  python3 mac_sha256.py setup <fkey>", file=sys.stderr)
        print("  python3 mac_sha256.py mac <fich> <fkey>", file=sys.stderr)
        print("  python3 mac_sha256.py ver <fich> <fkey>", file=sys.stderr)
        return 1

    cmd = sys.argv[1]
    if cmd == "setup" and len(sys.argv) == 3:
        cmd_setup(sys.argv[2])
        return 0
    if cmd == "mac" and len(sys.argv) == 4:
        cmd_mac(sys.argv[2], sys.argv[3])
        return 0
    if cmd == "ver" and len(sys.argv) == 4:
        cmd_ver(sys.argv[2], sys.argv[3])
        return 0

    print("invalid arguments", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
