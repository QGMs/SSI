#!/usr/bin/env python3
import struct
import sys
from pathlib import Path


KEY_SIZE = 32
BLOCK_SIZE = 64

K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_padding(msg_len: int) -> bytes:
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % BLOCK_SIZE) % BLOCK_SIZE)
    pad += struct.pack(">Q", msg_len * 8)
    return pad


def parse_state(mac_hex: str) -> list[int]:
    raw = bytes.fromhex(mac_hex)
    if len(raw) != 32:
        raise ValueError("invalid SHA256 MAC length")
    return list(struct.unpack(">8I", raw))


def compress(state: list[int], chunk: bytes) -> list[int]:
    w = list(struct.unpack(">16I", chunk)) + [0] * 48
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + s1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF,
    ]


def continue_sha256(state: list[int], extra: bytes, processed_len: int) -> str:
    data = extra + sha256_padding(processed_len + len(extra))
    cur = state[:]
    for i in range(0, len(data), BLOCK_SIZE):
        cur = compress(cur, data[i : i + BLOCK_SIZE])
    return "".join(f"{x:08x}" for x in cur)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python3 mac_sha256_attack.py <fich> <ext>", file=sys.stderr)
        return 1

    fich = sys.argv[1]
    ext = sys.argv[2].encode("utf-8")
    msg = Path(fich).read_bytes()
    mac_hex = Path(f"{fich}.mac").read_text(encoding="ascii").strip()

    original_len = KEY_SIZE + len(msg)
    glue = sha256_padding(original_len)
    forged_msg = msg + glue + ext
    processed_len = original_len + len(glue)
    forged_mac = continue_sha256(parse_state(mac_hex), ext, processed_len)

    Path(f"{fich}.ext").write_bytes(forged_msg)
    Path(f"{fich}.ext.mac").write_text(forged_mac, encoding="ascii")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
