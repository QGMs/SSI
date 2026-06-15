#!/usr/bin/env python3
import sys
from pathlib import Path


NONCE_SIZE = 16


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "Usage: python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>",
            file=sys.stderr,
        )
        return 1

    fctxt = sys.argv[1]
    pos = int(sys.argv[2])
    old = sys.argv[3].encode("utf-8")
    new = sys.argv[4].encode("utf-8")

    if len(old) != len(new):
        raise ValueError("ptxtAtPos and newPtxtAtPos must have the same length")
    if pos < 0:
        raise ValueError("pos must be non-negative")

    blob = bytearray(Path(fctxt).read_bytes())
    start = NONCE_SIZE + pos
    end = start + len(old)
    if len(blob) < end:
        raise ValueError("ciphertext too short for requested position")

    for i, (old_b, new_b) in enumerate(zip(old, new)):
        blob[start + i] ^= old_b ^ new_b

    Path(f"{fctxt}.attck").write_bytes(blob)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
