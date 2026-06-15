#!/bin/bash

# 3) python3 otp.py setup 30 otp.key
# 4) echo "Mensagem a cifrar" > ptxt.txt
# 5) python3 otp.py enc ptxt.txt otp.key > /dev/null
# 6) python3 otp.py dec ptxt.txt.enc otp.key > /dev/null
# 7) cat ptxt.txt.enc.dec

# Teste bad_otp + ataque:
# 8) python3 bad_otp.py setup 30 bad.key
# 9) python3 bad_otp.py enc ptxt.txt bad.key > /dev/null
# 10) python3 bad_otp_attack.py 30 ptxt.txt.enc TEXTO CIFRAR

# Resultado observado (OTP seguro):
# - Após setup+enc+dec com a mesma chave, o ficheiro ptxt.txt.enc.dec recupera exatamente "Mensagem a cifrar".
# - O ficheiro ptxt.txt.enc contém bytes cifrados (binário), por isso aparece "lixo" no cat.

# Resultado observado (bad_otp):
# - O ataque (bad_otp_attack.py) conseguiu recuperar o texto limpo "Mensagem a cifrar",
#   confirmando que a geração fraca da chave torna o sistema vulnerável.

# Q1:
# - Sim, há diferença: otp.py usa aleatoriedade criptograficamente segura (os.urandom),
#   enquanto bad_otp.py usa PRNG inseguro e previsível por brute force da semente.

# Q2:
# - Não há contradição com a segurança teórica do OTP.
# - O ataque explora uma implementação incorreta da chave (não aleatória o suficiente),
#   não o modelo ideal do one-time pad.

# Q3:
# - Reutilizar a mesma chave em duas mensagens permite obter C1 XOR C2 = M1 XOR M2.
# - Isto revela relações entre mensagens e facilita ataques,
#   violando o princípio essencial do OTP (chave única por mensagem).

cat > otp.py << 'PYEOF'
#!/usr/bin/env python3
import os
import sys


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def read_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage:\n  python3 otp.py setup <nbytes> <key_file>\n  python3 otp.py enc <msg_file> <key_file>\n  python3 otp.py dec <cipher_file> <key_file>")
        return 1

    op = sys.argv[1]

    if op == 'setup':
        n = int(sys.argv[2])
        key_file = sys.argv[3]
        key = os.urandom(n)
        write_file(key_file, key)
        return 0

    in_file = sys.argv[2]
    key_file = sys.argv[3]
    data = read_file(in_file)
    key = read_file(key_file)

    if len(key) < len(data):
        print("Key too short for input size", file=sys.stderr)
        return 1

    out = xor_bytes(data, key[:len(data)])

    if op == 'enc':
        out_file = in_file + '.enc'
    elif op == 'dec':
        out_file = in_file + '.dec'
    else:
        print("Invalid operation")
        return 1

    write_file(out_file, out)
    sys.stdout.buffer.write(out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
PYEOF

cat > bad_otp.py << 'PYEOF'
#!/usr/bin/env python3
import random
import sys


def bad_prng(n: int) -> bytes:
    """an INSECURE pseudo-random number generator"""
    random.seed(random.randbytes(2))
    return random.randbytes(n)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def read_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage:\n  python3 bad_otp.py setup <nbytes> <key_file>\n  python3 bad_otp.py enc <msg_file> <key_file>\n  python3 bad_otp.py dec <cipher_file> <key_file>")
        return 1

    op = sys.argv[1]

    if op == 'setup':
        n = int(sys.argv[2])
        key_file = sys.argv[3]
        key = bad_prng(n)
        write_file(key_file, key)
        return 0

    in_file = sys.argv[2]
    key_file = sys.argv[3]
    data = read_file(in_file)
    key = read_file(key_file)

    if len(key) < len(data):
        print("Key too short for input size", file=sys.stderr)
        return 1

    out = xor_bytes(data, key[:len(data)])

    if op == 'enc':
        out_file = in_file + '.enc'
    elif op == 'dec':
        out_file = in_file + '.dec'
    else:
        print("Invalid operation")
        return 1

    write_file(out_file, out)
    sys.stdout.buffer.write(out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
PYEOF

cat > bad_otp_attack.py << 'PYEOF'
#!/usr/bin/env python3
import random
import sys


def gen_bad_key(seed_bytes: bytes, n: int) -> bytes:
    random.seed(seed_bytes)
    return random.randbytes(n)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def read_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def looks_match(pt: bytes, words) -> bool:
    try:
        text = pt.decode('utf-8', errors='ignore').upper()
    except Exception:
        return False
    return any(w in text for w in words)


def main() -> int:
    if len(sys.argv) < 4:
        print("Usage: python3 bad_otp_attack.py <key_size> <cipher_file> <word1> [word2 ...]")
        return 1

    key_size = int(sys.argv[1])
    cfile = sys.argv[2]
    words = ["".join(c.upper() for c in w if c.isalpha()) for w in sys.argv[3:]]
    words = [w for w in words if w]

    ct = read_file(cfile)

    for s in range(65536):
        seed = s.to_bytes(2, 'big')
        key = gen_bad_key(seed, key_size)
        pt = xor_bytes(ct, key[:len(ct)])
        if looks_match(pt, words):
            try:
                print(pt.decode('utf-8', errors='ignore'))
            except Exception:
                print(pt)
            return 0

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
PYEOF

chmod +x otp.py bad_otp.py bad_otp_attack.py
