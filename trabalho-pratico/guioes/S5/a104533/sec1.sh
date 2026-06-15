#!/bin/bash

# 3) python3 cesar.py enc G "CartagoEstaNoPapo"
# 4) python3 cesar.py dec G "IGXZGMUKYZGTUVGVU"
# 5) python3 cesar_attack.py "IGXZGMUKYZGTUVGVU" BACO PAPO

# Comentario:
# - enc devolve IGXZGMUKYZGTUVGVU
# - dec devolve CARTAGOESTANOPAPO
# - attack devolve chave G e o texto "CARTAGOESTANOPAPO"

cat > cesar.py << 'PYEOF'
#!/usr/bin/env python3
import sys

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def preproc(s: str) -> str:
    return "".join(c.upper() for c in s if c.isalpha())


def shift_char(c: str, k: int, enc: bool) -> str:
    i = ord(c) - ord('A')
    if enc:
        return chr((i + k) % 26 + ord('A'))
    return chr((i - k) % 26 + ord('A'))


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: python3 cesar.py <enc|dec> <A-Z> <message>")
        return 1

    op = sys.argv[1]
    key = sys.argv[2].upper()
    msg = preproc(sys.argv[3])

    if op not in ("enc", "dec"):
        print("Invalid operation. Use enc or dec.")
        return 1
    if len(key) != 1 or key not in ALPHA:
        print("Invalid key. Use one letter A..Z.")
        return 1

    k = ord(key) - ord('A')
    out = "".join(shift_char(c, k, op == "enc") for c in msg)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PYEOF

cat > cesar_attack.py << 'PYEOF'
#!/usr/bin/env python3
import sys


def preproc(s: str) -> str:
    return "".join(c.upper() for c in s if c.isalpha())


def dec_with_shift(ct: str, k: int) -> str:
    out = []
    for c in ct:
        i = ord(c) - ord('A')
        out.append(chr((i - k) % 26 + ord('A')))
    return "".join(out)


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python3 cesar_attack.py <ciphertext> <word1> [word2 ...]")
        return 1

    ct = preproc(sys.argv[1])
    words = [preproc(w) for w in sys.argv[2:] if preproc(w)]
    if not ct or not words:
        return 0

    for k in range(26):
        pt = dec_with_shift(ct, k)
        if any(w in pt for w in words):
            print(chr(ord('A') + k))
            print(pt)
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PYEOF

chmod +x cesar.py cesar_attack.py

