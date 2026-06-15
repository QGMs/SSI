## Parte A - Buffer Overflow de Stack

### Exercício 1

- `-fno-stack-protector`: desativa o stack canary inserido pelo compilador para detetar corrupção da stack antes do retorno da função.
- `-z execstack`: marca a stack como executável. Neste trabalho o exploit pedido redireciona a execução para `secret_function`, por isso a execução na stack não é estritamente necessária, mas esta flag remove uma mitigação importante contra shellcode em stack.
- `-no-pie`: desativa Position Independent Executable, deixando os endereços do código fixos entre execuções quando o ASLR do código não atua.
- `-g`: inclui símbolos de debug para o GDB conseguir mostrar nomes, variáveis e informação de frame.

### Exercícios 2 e 3 - Resultados observados

- Endereço de `buffer`: `0x7fffffffe200`
- Endereço do `saved rip`: `0x7fffffffe248`
- Endereço de `secret_function`: `0x4011b6`
- Offset entre `buffer` e o `saved return address`: `72` bytes
- Payload usado no Exercício 3:
  - `python3 make_payload.py 72 0x4011b6 > payload.bin`
  - `./vuln "$(cat payload.bin)"`
- Resultado observado:
  - o programa redirecionou a execução para `secret_function`
  - apareceu `ACCESS GRANTED`

### Exercício 4 - Resultados observados

- Caso `gcc -o vuln vuln.c -z execstack -no-pie -g`:
  - `secret_function` mudou para `0x4011d6`
  - o programa terminou com `*** stack smashing detected ***`
  - o programa terminou com `Aborted (core dumped)`
  - isto confirma a atuação do stack canary

- Caso `gcc -o vuln vuln.c -fno-stack-protector -z execstack -g`:
  - o endereço de `secret_function` mudou entre execuções
  - o payload antigo deixou de apontar para o sítio certo
  - o programa terminou com `Segmentation fault (core dumped)`
  - isto é consistente com PIE/ASLR ativo

- Caso `gcc -o vuln vuln.c -g`:
  - o endereço de `secret_function` também mudou entre execuções
  - o programa terminou com `*** stack smashing detected ***`
  - o programa terminou com `Aborted (core dumped)`
  - isto é consistente com as mitigações por defeito (stack canary + PIE/ASLR)

### Exercício 4 - Explicação

- Stack canary ativo: o overflow falha com mensagem do tipo `*** stack smashing detected ***` porque o canary é corrompido antes do retorno.
- PIE/ASLR ativo: o endereço do código varia entre execuções, pelo que um payload construído com um endereço antigo deixa de ser fiável.
- Mitigações por defeito: a combinação de canary e PIE/ASLR torna o exploit significativamente menos estável ou diretamente inviável neste cenário simples.

### Exercício 5 - Resultados observados

- Compilação usada:
  - `gcc -o vuln_fixed vuln_fixed.c -g`
- Teste com entrada curta:
  - `./vuln_fixed "Hello"`
  - resultado: `[*] You entered: Hello`
  - resultado: `[*] Normal programme termination.`
- Teste com entrada longa:
  - `./vuln_fixed "$(python3 -c "print('A'*200)")"`
  - resultado: `[!] Input too long: max 63 bytes allowed.`
  - resultado: `[*] Normal programme termination.`

### Exercício 5 - Explicação

- A remediação segura precisa de:
  - substituir `strcpy` por uma alternativa segura;
  - validar explicitamente o comprimento;
  - compilar com as mitigações por defeito ativas.
- Em `vuln_fixed.c`, a estratégia usada é:
  - medir `strlen(input)`;
  - rejeitar a entrada se `input_len >= sizeof(buffer)`;
  - copiar com `memcpy(..., input_len + 1)` para incluir o `\0`.

## Parte B - Vulnerabilidade de String de Formato

### Exercício 6 - Resultados observados

- Compilação com warnings:
  - `gcc -o fmtvuln fmtvuln.c -g -Wall -Wformat -Wformat-security`
- Warning observado:
  - `warning: format not a string literal and no format arguments [-Wformat-security]`
- Execução benigna:
  - `./fmtvuln "Hello, world!"`
  - resultado: o programa imprimiu `Hello, world!` e terminou normalmente

### Exercício 6 - Explicação

- O warning principal do compilador indica que `printf(input)` usa uma string de formato não literal.
- Isto é útil como análise estática porque chama a atenção para uma API perigosa.
- Não é suficiente por si só porque:
  - depende das flags de warning usadas;
  - um warning pode ser ignorado;
  - nem todos os problemas de segurança são apanhados apenas pelo compilador.

### Exercício 7 - Resultados observados

- Com `%p`:
  - o programa imprimiu vários valores internos da stack/chamada
  - o sentinela apareceu como `0xcafebabe`
- Com `%x`:
  - o programa voltou a imprimir valores internos
  - o sentinela apareceu como `cafebabe`
  - os valores surgem em formato hexadecimal de largura mais curta do que com `%p`

### Exercício 7 - Explicação

- Com `%p` ou `%x`, o `printf` tenta consumir argumentos variádicos que o chamador nunca forneceu.
- Como a função `printf` não consegue saber, em runtime, quantos argumentos eram supostos existir além do format string, ela continua a ler valores dos registos/stack segundo as regras da ABI.
- `%p` é mais apropriado em 64 bits porque imprime um valor do tamanho de ponteiro; `%x` mostra apenas uma representação hexadecimal de largura menor, o que pode truncar informação relevante.

### Exercício 8 - Resultados observados

- Com 40 especificadores `%p`, o sentinela `0xcafebabe` apareceu no output.
- A posição observada foi a 8.ª.
- Com 50 especificadores `%p`, o sentinela voltou a aparecer na 8.ª posição.

### Exercício 8 - Explicação

- Este exercício demonstra que uma format string vulnerável pode divulgar informação sensível da stack.
- Um atacante pode recuperar:
  - endereços;
  - valores locais;
  - sentinelas;
  - eventualmente ponteiros úteis para derrotar ASLR ou orientar outros ataques.
- A zona afetada é a stack da chamada atual e, por extensão, dados temporários e endereços que ali estejam presentes.

### Exercício 9 - Resultados observados

- Compilação usada:
  - `gcc -o fmtvuln_fixed fmtvuln_fixed.c -g -Wall -Wformat -Wformat-security`
- Não foi observado qualquer warning de format string.
- Execução:
  - `./fmtvuln_fixed "%p %p %p %p"`
  - resultado: o programa imprimiu literalmente `%p %p %p %p`
  - resultado: não houve divulgação de valores da stack

### Exercício 9 - Explicação

- A correção segura é tratar a entrada como dados:
  - `printf("%s", input);`
- Isto faz com que `%p`, `%x` e outros especificadores presentes no input sejam impressos literalmente, em vez de interpretados como instruções de formatação.
