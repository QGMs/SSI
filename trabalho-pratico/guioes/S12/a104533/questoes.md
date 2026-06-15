# Semana 12 - Injecao SQL e de Comandos

## Exercicio 1 - Reconhecimento de SQL injection

### Pesquisa normal: `Welcome`

Resultado:

```text
[DEBUG] Executing SQL: SELECT id, title, body FROM notes WHERE title LIKE '%Welcome%'
  [1] Welcome: This is your first note.
```

Isto e o comportamento normal. A aplicacao procura notas cujo titulo contenha `Welcome`.

### Payload 1: `' OR '1'='1`

Resultado:

```text
[DEBUG] Executing SQL: SELECT id, title, body FROM notes WHERE title LIKE '%' OR '1'='1%'
  [1] Welcome: This is your first note.
  [2] Reminder: Submit the SSI lab report on time.
  [3] Secret: The admin password is hunter2.
```

Este payload fecha a string do `LIKE` e altera a logica da clausula `WHERE`. Na pratica, a pesquisa deixa de filtrar pelo titulo 
e passa a devolver todas as notas, incluindo a nota `Secret`.

### Payload 2: `' UNION SELECT 1, sql, '' FROM sqlite_master --`

Resultado:

```text
[DEBUG] Executing SQL: SELECT id, title, body FROM notes WHERE title LIKE '%' UNION SELECT 1, sql, '' FROM sqlite_master --%'
  [1] CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, body TEXT):
  [1] Welcome: This is your first note.
  [2] Reminder: Submit the SSI lab report on time.
  [3] Secret: The admin password is hunter2.
```

Aqui o atacante usa `UNION SELECT` para juntar ao resultado original informacao da tabela interna `sqlite_master`,
onde o SQLite guarda o schema. Isto permite descobrir a estrutura da base de dados.

### Payload 3: `' UNION SELECT 1, title, body FROM notes --`

Resultado:

```text
[DEBUG] Executing SQL: SELECT id, title, body FROM notes WHERE title LIKE '%' UNION SELECT 1, title, body FROM notes --%'
  [1] Reminder: Submit the SSI lab report on time.
  [1] Secret: The admin password is hunter2.
  [1] Welcome: This is your first note.
  [2] Reminder: Submit the SSI lab report on time.
  [3] Secret: The admin password is hunter2.
```

Este payload injeta uma segunda query que volta a ler diretamente a tabela `notes`.
Ou seja, o atacante ganha controlo real sobre a query executada.

### O que cada payload faz e porque funciona

- O primeiro payload transforma a condicao do `WHERE` numa expressao sempre verdadeira.
- O segundo usa `UNION SELECT` para ler o schema da base de dados.
- O terceiro usa `UNION SELECT` para voltar a ler diretamente a tabela de notas.

Tudo isto funciona porque a aplicacao concatena texto do utilizador diretamente na query SQL.
O input deixa de ser apenas dados e passa a ser interpretado como codigo SQL.

### Que informacao pode um atacante extrair?

Um atacante pode extrair:

- todas as notas da tabela
- segredos guardados nas notas
- a estrutura das tabelas e colunas
- potencialmente dados de outras tabelas da mesma base de dados

## Exercicio 2 - Command injection

### Payload 1: `note.txt`

Resultado:

```text
[DEBUG] Executing command: echo 'Title: Welcome
Body: This is your first note.' > note.txt
  Note exported to note.txt
```

Aqui o comportamento e normal: a nota e exportada para o ficheiro.

### Payload 2: `note.txt; cat /etc/passwd`

Resultado:

```text
root:x:0:0:root:/root:/bin/bash
...
[DEBUG] Executing command: echo 'Title: Welcome
Body: This is your first note.' > note.txt; cat /etc/passwd
  Note exported to note.txt; cat /etc/passwd
```

O comando extra depois do `;` tambem e executado. Isto mostra que o nome do ficheiro nao esta a ser tratado como dado,
mas sim como parte da linha de comandos.

### Payload 3: `note.txt; id; whoami`

Resultado:

```text
uid=1000(<utilizador>) gid=1000(<grupo>) groups=...
<utilizador>
[DEBUG] Executing command: echo 'Title: Welcome
Body: This is your first note.' > note.txt; id; whoami
  Note exported to note.txt; id; whoami
```

Este payload prova que o atacante consegue executar comandos arbitrarios e descobrir com que privilegios o processo esta a correr.

### Payload 4: `` `ls -la` ``

Resultado:

```text
[DEBUG] Executing command: echo 'Title: Welcome
Body: This is your first note.' > `ls -la`
  Note exported to `ls -la`
sh: ... File name too long
```

Mesmo quando o resultado final e erro, a shell tenta expandir os backticks antes de executar o resto do comando.
Isso ja chega para demonstrar a vulnerabilidade.

### Porque a aplicacao e vulneravel?

O problema esta em:

```python
cmd = f"echo 'Title: {row[0]}\nBody: {row[1]}' > {filename}"
os.system(cmd)
```

Ou seja, o nome do ficheiro entra diretamente numa string de shell. Assim, metacaracteres como `;` e 
backticks deixam de ser texto normal e passam a ter significado para a shell.

### O que um atacante poderia alcancar num servidor real?

Num servidor real, um atacante poderia:

- ler ficheiros locais sensiveis
- descobrir informacao do sistema
- executar comandos arbitrarios
- apagar ou alterar ficheiros
- usar os privilegios do utilizador do servico para causar mais dano

## Exercicio 3 - Remediacao segura (SQL injection)

### Funcao corrigida

```python
def search_notes(query):
    """Pesquisa segura usando placeholders SQL."""
    statement = "SELECT id, title, body FROM notes WHERE title LIKE ? ORDER BY id"
    parameter = f"%{query}%"
    print(f"[DEBUG] Executing SQL: {statement} | params=({parameter!r},)")

    try:
        with open_db() as conn:
            rows = conn.execute(statement, (parameter,)).fetchall()
    except sqlite3.Error as exc:
        print(f"  SQL error: {exc}")
        return

    if not rows:
        print("  No notes found.")
        return

    for row in rows:
        print(f"  [{row['id']}] {row['title']}: {row['body']}")
```

### Porque esta correcao e segura

- a query deixa de ser montada por concatenacao
- o input do utilizador passa a ser um parametro
- o SQLite trata o valor como dado literal, nao como SQL executavel
- os wildcards `%` continuam a funcionar porque sao aplicados ao parametro

### Inputs usados depois da correcao

Foram repetidos os mesmos payloads do Exercicio 1:

```text
' OR '1'='1
' UNION SELECT 1, sql, '' FROM sqlite_master --
' UNION SELECT 1, title, body FROM notes --
```

### Resultado observado depois da correcao

```text
[DEBUG] Executing SQL: SELECT id, title, body FROM notes WHERE title LIKE ? ORDER BY id | params=("%' OR '1'='1%",)
  No notes found.

[DEBUG] Executing SQL: SELECT id, title, body FROM notes WHERE title LIKE ? ORDER BY id | params=("%' UNION SELECT 1, sql, '' FROM sqlite_master --%",)
  No notes found.
```

Ou seja, os payloads deixam de alterar a query e passam a ser tratados como texto normal de pesquisa.

## Exercicio 4 - Remediacao segura (command injection)

### Funcao corrigida

```python
def export_note(note_id):
    """Escreve a nota para um ficheiro sem invocar qualquer shell."""
    row = fetch_note(note_id)
    if row is None:
        print("  Note not found.")
        return

    filename = input("  Enter filename to export to: ").strip()
    if not is_valid_export_name(filename):
        print("  Invalid filename. Use a simple local filename with letters, digits, ., _ or -.")
        return

    EXPORT_DIR.mkdir(exist_ok=True)
    destination = EXPORT_DIR / filename
    content = f"Title: {row['title']}\nBody: {row['body']}\n"
    destination.write_text(content, encoding="utf-8")
    print(f"  Note exported to {destination}")
```

### Porque esta correcao e segura

- `os.system()` desaparece
- deixa de existir uma shell para interpretar `;`, backticks ou pipes
- o nome do ficheiro e validado
- a exportacao fica limitada a uma pasta controlada (`exports/`)

### Inputs usados depois da correcao

Foram repetidos os mesmos inputs do Exercicio 2:

```text
note.txt
note.txt; cat /etc/passwd
note.txt; id; whoami
`ls -la`
```

### Resultado observado depois da correcao

```text
note.txt
  Note exported to exports/note.txt

note.txt; cat /etc/passwd
  Invalid filename. Use a simple local filename with letters, digits, ., _ or -.

note.txt; id; whoami
  Invalid filename. Use a simple local filename with letters, digits, ., _ or -.

`ls -la`
  Invalid filename. Use a simple local filename with letters, digits, ., _ or -.
```

Nenhum dos payloads maliciosos volta a ser executado.

## Exercicio 5 - Reflexao

Buffer overflows, format strings, SQL injection e command injection parecem falhas diferentes, mas partilham a mesma causa de fundo: o programa
perde controlo sobre a fronteira entre dados e mecanismos internos. Num buffer overflow, bytes extra passam o limite de um buffer e corrompem
memoria adjacente. Numa format string, o input deixa de ser texto normal e passa a ser interpretado por `printf` como instrucoes de formatacao.
Em SQL injection e command injection, texto do utilizador e tratado como codigo por outro interpretador. Em todos os casos,
o software mistura dados e comandos.

A validacao de input, sozinha, nao chega porque e facil esquecer metacaracteres, combinacoes inesperadas ou contextos diferentes.
Mesmo um filtro razoavel pode falhar se a arquitetura continuar baseada em concatenacao de strings ou invocacao desnecessaria da shell.
A defesa forte aparece quando a estrutura do programa impede essa mistura.

Os principios de parametrizacao e privilegio minimo aplicam-se diretamente aqui. 
Na Semana 12, usamos placeholders SQL e removemos a shell da exportacao. 
Na Semana 11, o equivalente foi usar funcoes com limites explicitos e formatos literais fixos.
Menos privilegios significam menos dano se a falha existir.

Buffer overflow e format string diferem no mecanismo. O buffer overflow escreve para alem do espaco reservado e pode corromper variaveis,canaries e enderecos de retorno.
A format string nao precisa de ultrapassar um buffer; convence `printf` a ler ou interpretar memoria que nao devia expor.
