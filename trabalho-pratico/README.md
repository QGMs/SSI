# Trabalho Pratico SSI

Sistema de chat seguro cliente-servidor, implementado em Python com a biblioteca `cryptography`.

## O que esta implementado

- canal cliente-servidor autenticado e cifrado com `X25519 + HKDF + AES-GCM`
- autenticacao do servidor com certificado emitido por uma CA local
- certificados de utilizador emitidos pelo servidor/CA
- mensagens fim-a-fim cifradas e assinadas
- mensagens offline com armazenamento opaco no servidor
- forward secrecy ao nivel das mensagens offline com signed prekey + one-time prekeys
- perfis locais protegidos com password (`PBKDF2 + AES-GCM`)
- shell interativa para utilizadores e gestao de contactos
- relatorio tecnico em Markdown

## Dependencias

```bash
python3 -m pip install -r requirements.txt
```

## Arranque rapido

Numa primeira terminal:

```bash
cd trabalho
python3 server.py --host 127.0.0.1 --port 9000 --data-dir server_state
```

O servidor cria automaticamente:

- `server_state/ca_cert.pem`
- `server_state/server_cert.pem`
- `server_state/server.db`

Noutra terminal, criar o perfil local do primeiro utilizador:

```bash
cd trabalho
python3 client.py init --username alice --profile alice.json
python3 client.py register --profile alice.json --host 127.0.0.1 --port 9000 --ca-cert server_state/ca_cert.pem
```

Repetir para outro utilizador:

```bash
cd trabalho
python3 client.py init --username bob --profile bob.json
python3 client.py register --profile bob.json --host 127.0.0.1 --port 9000 --ca-cert server_state/ca_cert.pem
```

Entrar na shell segura:

```bash
cd trabalho
python3 client.py shell --profile alice.json --host 127.0.0.1 --port 9000 --ca-cert server_state/ca_cert.pem
```

Exemplos de comandos dentro da shell:

```text
help
users
contacts add bob
send bob "Ola Bob, isto vai cifrado ponta-a-ponta."
fetch
sync
quit
```

## Notas de seguranca

- o servidor ve usernames, certificados, timestamps e envelopes opacos, mas nao o plaintext das mensagens
- cada mensagem usa uma one-time prekey do destinatario, consumida no servidor e removida localmente apos a decifragem
- os contactos sao guardados localmente e sincronizados com o servidor sob a forma de blob cifrado

## Testes

```bash
cd trabalho
python3 -m unittest tests.test_integration -v
```

Os testes cobrem:

- emissao de certificados pela CA
- handshake autenticado
- envio offline de mensagens
- decifragem correta pelo destinatario
- consumo da one-time prekey e propriedade pratica de forward secrecy
- rejeicao de envelopes E2EE com metadata inconsistente
