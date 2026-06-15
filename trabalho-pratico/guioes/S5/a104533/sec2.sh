#!/bin/bash

# 3) python3 vigenere.py enc BACO "CifraIndecifravel"
# 4) python3 vigenere.py dec BACO "DIHFBIPRFCKTSAXSM"
# 5) python3 vigenere_attack.py 3 "PGRGARHSFHPRGCVHOJHWEPZRSCJFIVSOFRWUTBKPZGGOZPZLHWKPBR" PAPO PRAIA

# Comentario:
# - enc devolve DIHFBIPRFCKTSAXSM
# - dec devolve CIFRAINDECIFRAVEL
# - attack devolve chave POR e o texto "ASARMASEOSBAROESASSINALADOSQUEDAOCIDENTALPRAIALUSITANA"

# Se nao encontrar match com o valor default (10), aumentar topn (ex.: 10, 13 ou 26).
# topn=26 faz procura completa

cat > vigenere.py << 'PYEOF'
#!/usr/bin/env python3
import sys


def preproc(s: str) -> str:
    return "".join(c.upper() for c in s if c.isalpha())


def apply_vigenere(msg: str, key: str, enc: bool) -> str:
    out = []
    for i, c in enumerate(msg):
        m = ord(c) - ord('A')
        k = ord(key[i % len(key)]) - ord('A')
        if enc:
            out.append(chr((m + k) % 26 + ord('A')))
        else:
            out.append(chr((m - k) % 26 + ord('A')))
    return "".join(out)


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: python3 vigenere.py <enc|dec> <KEY> <message>")
        return 1

    op = sys.argv[1]
    key = preproc(sys.argv[2])
    msg = preproc(sys.argv[3])

    if op not in ("enc", "dec"):
        print("Invalid operation. Use enc or dec.")
        return 1
    if not key:
        print("Invalid key. Use letters A..Z.")
        return 1

    print(apply_vigenere(msg, key, op == "enc"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PYEOF

cat > vigenere_attack.py << 'PYEOF'
#!/usr/bin/env python3
import itertools
import math
import sys

PT_FREQ = {
    'A': 0.1463, 'E': 0.1257, 'O': 0.1073, 'S': 0.0781, 'R': 0.0653,
    'I': 0.0618, 'N': 0.0505, 'D': 0.0499, 'M': 0.0474, 'U': 0.0463,
    'T': 0.0434, 'C': 0.0388, 'L': 0.0278, 'P': 0.0252, 'V': 0.0167,
    'G': 0.0130, 'H': 0.0128, 'Q': 0.0120, 'B': 0.0104, 'F': 0.0102,
    'Z': 0.0047, 'J': 0.0040, 'X': 0.0021, 'K': 0.0002, 'W': 0.0001,
    'Y': 0.0001,
}


def preproc(s: str) -> str:
    return "".join(c.upper() for c in s if c.isalpha())


def dec_caesar(chunk: str, k: int) -> str:
    out = []
    for c in chunk:
        i = ord(c) - ord('A')
        out.append(chr((i - k) % 26 + ord('A')))
    return "".join(out)


def chi_square_score(text: str) -> float:
    if not text:
        return float('inf')
    n = len(text)
    counts = {chr(ord('A') + i): 0 for i in range(26)}
    for c in text:
        counts[c] += 1
    score = 0.0
    for c in counts:
        expected = PT_FREQ.get(c, 0.0001) * n
        if expected <= 0:
            continue
        diff = counts[c] - expected
        score += (diff * diff) / expected
    return score


def decrypt_vigenere(ct: str, key_shifts):
    out = []
    klen = len(key_shifts)
    for i, c in enumerate(ct):
        m = (ord(c) - ord('A') - key_shifts[i % klen]) % 26
        out.append(chr(m + ord('A')))
    return "".join(out)


def key_to_str(shifts):
    return "".join(chr(ord('A') + k) for k in shifts)


def top_shifts_for_slice(slice_text: str, topn: int = 10):
    scored = []
    for k in range(26):
        pt = dec_caesar(slice_text, k)
        scored.append((chi_square_score(pt), k))
    scored.sort(key=lambda x: x[0])
    return [k for _, k in scored[:topn]]


def main() -> int:
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py <key_len> <ciphertext> <word1> [word2 ...]")
        return 1

    try:
        key_len = int(sys.argv[1])
    except ValueError:
        print("key_len must be integer")
        return 1

    ct = preproc(sys.argv[2])
    words = [preproc(w) for w in sys.argv[3:] if preproc(w)]

    if key_len <= 0 or not ct or not words:
        return 0

    slices = [ct[i::key_len] for i in range(key_len)]
    candidates = [top_shifts_for_slice(s, topn=10) for s in slices]

    for ks in itertools.product(*candidates):
        pt = decrypt_vigenere(ct, ks)
        if any(w in pt for w in words):
            print(key_to_str(ks))
            print(pt)
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PYEOF

chmod +x vigenere.py vigenere_attack.py

