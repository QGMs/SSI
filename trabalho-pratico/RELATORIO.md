# Relatorio do Trabalho Pratico

## Sistema de Chat Seguro com End-to-End Encryption

Unidade Curricular: Seguranca de Sistemas Informaticos

Ano letivo: 2025/2026

---

## Indice

1. Introducao
2. Arquitetura Funcional
3. Funcionalidades Implementadas
4. Valorizacoes Implementadas
5. Modelo de Seguranca
6. Metodologia de Gestao de Chaves
7. Protocolo de Comunicacao
8. Armazenamento e Persistencia
9. Fundamentacao Criptografica
10. Relacao com a Materia da Unidade Curricular
11. Testes e Validacao
12. Limitacoes e Melhorias Futuras
13. Conclusao

---

## 1. Introducao

O presente relatorio descreve a solucao desenvolvida para o trabalho pratico de Seguranca de Sistemas Informaticos. O objetivo do projeto foi implementar um sistema de conversacao seguro, em arquitetura cliente-servidor, que garanta confidencialidade, integridade e autenticidade das comunicacoes, incluindo protecao fim-a-fim do conteudo das mensagens.

A solucao foi implementada em Python, recorrendo a biblioteca `cryptography` para as primitivas criptograficas, conforme exigido no enunciado. O sistema permite que diferentes utilizadores criem perfis locais, se registem junto de um servidor, estabelecam sessoes autenticadas, adicionem contactos, enviem mensagens cifradas ponta-a-ponta e recebam mensagens que tenham sido armazenadas enquanto estavam offline.

O servidor atua como ponto central de coordenacao. E responsavel por gerir utilizadores, emitir e armazenar certificados, distribuir material criptografico publico necessario a entrega de mensagens e guardar envelopes cifrados pendentes. No entanto, o servidor foi desenhado segundo o modelo honesto-mas-curioso: e confiado para executar corretamente a logica funcional do servico, mas nao deve conseguir ler o conteudo das mensagens dos utilizadores.

Foram implementadas tres valorizacoes principais:

- Entidade de Certificacao (PKI) local;
- Mensagens offline;
- Forward secrecy pratica para mensagens offline.

---

## 2. Arquitetura Funcional

### 2.1. Visao geral

O sistema e composto por duas aplicacoes principais:

- `server.py`: servidor central do sistema;
- `client.py`: cliente utilizado por cada utilizador.

Internamente, o codigo esta organizado na package `secure_chat/`, separando as responsabilidades criptograficas, persistencia, gestao de perfis, protocolo do servidor e protocolo do cliente.

O servidor escuta ligacoes TCP e processa pedidos dos clientes. O cliente disponibiliza uma interface de linha de comandos, atraves da qual o utilizador pode criar o seu perfil, registar-se, entrar numa shell interativa, gerir contactos, enviar mensagens e receber mensagens pendentes.

### 2.2. Componentes do servidor

O servidor e responsavel por:

- criar ou carregar a CA local;
- criar ou carregar o certificado do proprio servidor;
- registar utilizadores;
- emitir certificados de utilizador;
- guardar certificados e metadados em SQLite;
- armazenar blobs cifrados de contactos;
- guardar signed prekeys e one-time prekeys publicas;
- entregar delivery bundles aos emissores;
- armazenar envelopes cifrados de mensagens offline;
- entregar mensagens pendentes ao destinatario;
- apagar mensagens confirmadas atraves de `ack`.

O servidor nao armazena chaves privadas dos clientes nem plaintext das mensagens.

### 2.3. Componentes do cliente

O cliente e responsavel por:

- criar e proteger o perfil local;
- gerar chaves criptograficas de identidade;
- gerar signed prekeys e one-time prekeys;
- validar certificados;
- autenticar o servidor;
- autenticar-se perante o servidor;
- gerir contactos;
- cifrar e assinar mensagens;
- decifrar e verificar mensagens recebidas;
- remover one-time prekeys apos uso.

### 2.4. Organizacao dos modulos

Os principais modulos sao:

- `secure_chat/crypto.py`: primitivas criptograficas, certificados, derivacao de chaves, cifragem E2EE e validacao;
- `secure_chat/profile.py`: criacao, carregamento e armazenamento cifrado dos perfis locais;
- `secure_chat/server_app.py`: logica do servidor, handshake, registo, login e pedidos autenticados;
- `secure_chat/client_app.py`: logica do cliente, comandos e shell interativa;
- `secure_chat/storage.py`: persistencia SQLite;
- `secure_chat/session.py`: canal seguro cliente-servidor;
- `secure_chat/framing.py`: enquadramento das mensagens TCP;
- `secure_chat/utils.py`: funcoes auxiliares.

### 2.5. Camadas de protecao

A arquitetura distingue duas camadas de protecao:

1. Canal cliente-servidor;
2. Cifragem ponta-a-ponta cliente-cliente.

O canal cliente-servidor protege os pedidos operacionais feitos ao servidor. A cifragem ponta-a-ponta protege o conteudo das mensagens entre utilizadores, impedindo que o servidor leia o plaintext.

---

## 3. Funcionalidades Implementadas

### 3.1. Criacao de perfis locais

Cada utilizador cria um perfil local atraves do comando:

```bash
python3 client.py init --username alice --profile alice.json
```

O perfil contem o material privado do utilizador, incluindo a chave de assinatura, a chave de identidade `X25519`, contactos e prekeys. O material privado e cifrado localmente com uma chave derivada da password do utilizador atraves de `PBKDF2HMAC-SHA256`.

### 3.2. Registo de utilizadores

Depois de criado o perfil, o utilizador regista-se no servidor:

```bash
python3 client.py register --profile alice.json --host 127.0.0.1 --port 9000 --ca-cert server_state/ca_cert.pem
```

Durante o registo, o cliente estabelece um canal seguro com o servidor, envia as suas chaves publicas e prova a posse da chave privada de assinatura. O servidor emite um certificado para o utilizador e armazena as suas prekeys publicas.

### 3.3. Autenticacao e shell interativa

O utilizador entra na shell com:

```bash
python3 client.py shell --profile alice.json --host 127.0.0.1 --port 9000 --ca-cert server_state/ca_cert.pem
```

Antes de aceitar comandos, o cliente autentica o servidor e autentica-se perante este. A shell permite usar comandos como:

- `users`;
- `contacts list`;
- `contacts add <utilizador>`;
- `contacts remove <utilizador>`;
- `send <utilizador> <mensagem>`;
- `fetch`;
- `sync`;
- `quit`.

### 3.4. Gestao de contactos

Os contactos sao guardados como certificados completos, nao apenas como chaves publicas cruas. Quando um utilizador adiciona um contacto, o cliente:

1. pede o certificado ao servidor;
2. valida o certificado com a CA local;
3. verifica se o `Common Name` corresponde ao username esperado;
4. fixa o certificado localmente.

Se posteriormente o servidor devolver um certificado diferente para esse contacto, a operacao e bloqueada. Isto reduz o risco de substituicao inesperada de identidade.

### 3.5. Envio e rececao de mensagens

Para enviar uma mensagem, o emissor pede ao servidor um delivery bundle do destinatario. Esse bundle contem:

- certificado do destinatario;
- signed prekey ativa;
- uma one-time prekey.

O cliente emissor valida o certificado, valida a signed prekey, deriva uma chave de mensagem, cifra o plaintext com `AES-GCM` e assina o envelope com `Ed25519`. O servidor recebe apenas o envelope cifrado.

O destinatario, ao executar `fetch`, recebe os envelopes pendentes, valida o certificado do remetente, verifica a assinatura do envelope, deriva a mesma chave de mensagem e decifra o conteudo localmente.

---

## 4. Valorizacoes Implementadas

### 4.1. Entidade de Certificacao (PKI)

Foi implementada uma PKI local. No primeiro arranque, o servidor cria uma CA self-signed e guarda:

- chave privada da CA;
- certificado raiz da CA (`ca_cert.pem`).

O servidor tambem possui um certificado proprio, emitido pela CA, com `CN=secure-chat-server`. Os clientes usam o certificado da CA como ancora de confianca para validar o certificado do servidor.

Durante o registo, o servidor emite certificados para os utilizadores. Cada certificado associa:

- username;
- chave publica `Ed25519`;
- chave publica `X25519` de identidade.

A chave `X25519` do utilizador e colocada numa extensao X.509 propria, permitindo que o certificado transporte a identidade necessaria para assinatura e para E2EE.

### 4.2. Mensagens offline

O sistema suporta mensagens offline. O destinatario nao precisa de estar ligado no momento em que o emissor envia a mensagem, porque publica previamente:

- uma signed prekey;
- varias one-time prekeys.

Quando o emissor quer enviar uma mensagem, pede ao servidor um delivery bundle do destinatario. O servidor devolve o material publico necessario e armazena o envelope cifrado ate o destinatario executar `fetch`.

Esta funcionalidade permite comunicacao assincrona sem expor o plaintext ao servidor.

### 4.3. Forward secrecy

Foi implementada forward secrecy pratica para mensagens offline atraves de one-time prekeys.

Cada mensagem depende de uma one-time prekey unica do destinatario. O servidor remove essa one-time prekey da pool quando a entrega num delivery bundle. Depois de decifrar a mensagem, o destinatario remove localmente a chave privada correspondente.

Assim, mesmo que no futuro um atacante comprometa a chave estatica `X25519` do destinatario e a signed prekey, isso nao basta para recuperar mensagens antigas que tambem dependiam da one-time prekey ja removida.

Esta abordagem e inspirada em prekeys/X3DH, mas nao pretende ser uma implementacao completa do protocolo Signal.

---

## 5. Modelo de Seguranca

### 5.1. Assuncoes

O modelo de seguranca considera que:

- um atacante pode observar o trafego de rede;
- um atacante pode modificar ou injetar mensagens na rede;
- um atacante pode tentar ataques de man-in-the-middle;
- o servidor e honesto-mas-curioso;
- os clientes conhecem previamente o certificado correto da CA local.

O servidor e confiado para gerir o estado funcional do sistema, mas nao para preservar a confidencialidade dos conteudos se estes lhe fossem entregues em claro. Por isso, as mensagens sao cifradas ponta-a-ponta.

### 5.2. Garantias fornecidas

O sistema fornece:

- autenticidade do servidor;
- autenticidade dos utilizadores;
- confidencialidade e integridade do canal cliente-servidor;
- confidencialidade fim-a-fim das mensagens;
- integridade e autenticidade dos envelopes E2EE;
- protecao contra substituicao de certificados de contactos;
- entrega offline de mensagens cifradas;
- forward secrecy pratica ao nivel das mensagens offline.

### 5.3. Informacao visivel ao servidor

O servidor consegue observar:

- usernames;
- certificados;
- timestamps;
- remetente e destinatario dos envelopes;
- IDs de prekeys;
- tamanho aproximado dos envelopes;
- blobs cifrados de contactos.

O servidor nao consegue observar:

- plaintext das mensagens;
- chaves privadas dos utilizadores;
- passwords dos perfis;
- lista de contactos em claro.

### 5.4. Protecao contra MITM

A protecao contra MITM resulta da combinacao de:

- validacao do certificado do servidor com a CA;
- assinatura do transcript do handshake pelo servidor;
- autenticacao posterior do cliente com a sua chave `Ed25519`;
- validacao dos certificados de utilizador;
- assinatura das mensagens E2EE pelo remetente.

Um atacante que substitua chaves efemeras no handshake nao consegue produzir a assinatura valida do servidor. Um atacante que tente substituir a identidade de um utilizador nao consegue apresentar um certificado valido emitido pela CA para o username esperado.

---

## 6. Metodologia de Gestao de Chaves

### 6.1. Chaves da CA

A CA local possui uma chave privada `Ed25519` e um certificado self-signed. Esta CA e criada no servidor e usada para emitir:

- certificado do servidor;
- certificados dos utilizadores.

O certificado publico da CA (`ca_cert.pem`) e distribuido aos clientes como ancora de confianca.

### 6.2. Chaves do servidor

O servidor possui uma chave privada `Ed25519` e um certificado assinado pela CA. A chave privada do servidor e usada para assinar o transcript do handshake, permitindo ao cliente autenticar a entidade com quem esta a estabelecer o canal seguro.

### 6.3. Chaves dos utilizadores

Cada utilizador possui:

- chave privada `Ed25519`, usada para autenticacao e assinatura;
- chave privada `X25519` de identidade, usada no E2EE;
- signed prekey `X25519`;
- conjunto de one-time prekeys `X25519`;
- chave simetrica para cifrar o blob de contactos.

As chaves privadas dos utilizadores nunca sao enviadas ao servidor. Permanecem no perfil local cifrado.

### 6.4. Protecao do perfil

O perfil local e protegido da seguinte forma:

1. gera-se um `salt` aleatorio;
2. deriva-se uma chave a partir da password usando `PBKDF2HMAC-SHA256`;
3. cifra-se o material privado com `AES-GCM`;
4. guarda-se o resultado no campo `private_blob`.

Esta abordagem protege as chaves privadas caso o ficheiro de perfil seja copiado por terceiros.

### 6.5. Gestao de prekeys

Cada cliente mantem uma signed prekey ativa e um conjunto de one-time prekeys. Quando necessario, o cliente gera novas one-time prekeys e publica as chaves publicas no servidor.

As one-time prekeys sao usadas uma vez. O servidor remove a prekey publica quando a entrega num bundle, e o destinatario remove a chave privada local apos decifrar a mensagem.

---

## 7. Protocolo de Comunicacao

### 7.1. Handshake cliente-servidor

Cada ligacao com o servidor comeca com um handshake:

1. O cliente gera uma chave efemera `X25519`;
2. O cliente envia `client_hello`;
3. O servidor gera uma chave efemera `X25519`;
4. O servidor responde com `server_hello`, certificado e assinatura;
5. O cliente valida o certificado do servidor;
6. O cliente verifica a assinatura do transcript;
7. Ambos calculam o segredo partilhado `X25519`;
8. Ambos derivam chaves com `HKDF`;
9. O canal passa a usar `AES-GCM`.

O transcript do handshake e incluido na derivacao das chaves, ligando as chaves de sessao aos valores publicos trocados.

### 7.2. Canal seguro

O canal seguro usa:

- chave de envio;
- chave de rececao;
- prefixos de nonce separados por direcao;
- contadores monotonicamente crescentes;
- `AES-GCM`.

Esta separacao evita reutilizacao de nonce com a mesma chave e fornece confidencialidade, integridade e autenticacao ao trafego cliente-servidor.

### 7.3. Registo

Durante o registo, o cliente envia pelo canal seguro:

- username;
- chave publica `Ed25519`;
- chave publica `X25519`;
- prova de posse da chave `Ed25519`;
- signed prekey;
- one-time prekeys;
- blob cifrado de contactos.

O servidor valida estes dados, emite o certificado de utilizador e guarda o material publico necessario ao funcionamento do sistema.

### 7.4. Login

Durante o login, o cliente assina o transcript do handshake com a sua chave `Ed25519`. O servidor valida essa assinatura com a chave publica presente no certificado do utilizador.

Desta forma, a autenticacao do cliente baseia-se na posse da chave privada, nao no envio de passwords ao servidor.

### 7.5. Envio E2EE

Para cifrar uma mensagem, o emissor calcula material DH a partir de:

1. chave de identidade do emissor x signed prekey do destinatario;
2. chave efemera do emissor x chave de identidade do destinatario;
3. chave efemera do emissor x signed prekey do destinatario;
4. chave efemera do emissor x one-time prekey do destinatario.

O material resultante e processado com `HKDF`, produzindo uma chave de mensagem. O plaintext e cifrado com `AES-GCM`, usando como dados autenticados a metadata essencial do envelope. Por fim, o envelope e assinado pelo remetente com `Ed25519`.

### 7.6. Rececao E2EE

Ao receber uma mensagem, o destinatario:

1. valida o certificado do remetente;
2. verifica a assinatura do envelope;
3. identifica as prekeys usadas atraves dos IDs no envelope;
4. recalcula o mesmo material DH;
5. deriva a chave de mensagem com `HKDF`;
6. decifra o payload com `AES-GCM`;
7. remove a one-time prekey usada;
8. confirma a rececao ao servidor com `ack`.

---

## 8. Armazenamento e Persistencia

### 8.1. Base de dados do servidor

O servidor usa SQLite para persistencia. A base de dados contem:

- `users`: utilizadores, certificados e blob cifrado de contactos;
- `messages`: envelopes cifrados pendentes;
- `signed_prekeys`: signed prekeys dos utilizadores;
- `one_time_prekeys`: one-time prekeys publicas ainda disponiveis.

As mensagens sao guardadas como envelopes JSON cifrados. O plaintext nunca e armazenado pelo servidor.

### 8.2. Ficheiros gerados pelo servidor

O servidor cria, dentro da pasta indicada por `--data-dir`:

- `ca_identity.json`;
- `ca_cert.pem`;
- `server_identity.json`;
- `server_cert.pem`;
- `server.db`.

Estes ficheiros representam estado de execucao e nao devem ser confundidos com codigo fonte.

### 8.3. Perfis dos clientes

Cada cliente guarda o seu estado num ficheiro JSON, por exemplo `alice.json`. Este ficheiro contem metadata publica e um `private_blob` cifrado.

O `private_blob` contem chaves privadas, contactos, signed prekeys e one-time prekeys.

---

## 9. Fundamentacao Criptografica

### 9.1. `Ed25519`

Foi escolhido para assinaturas digitais. E usado para assinar certificados, transcripts, signed prekeys e envelopes E2EE. A sua utilizacao permite garantir autenticidade e integridade dos dados assinados.

### 9.2. `X25519`

Foi escolhido para acordo de chaves Diffie-Hellman moderno. E usado no handshake cliente-servidor e na derivacao das chaves E2EE das mensagens.

### 9.3. `HKDF`

O segredo produzido por Diffie-Hellman nao deve ser usado diretamente como chave simetrica. Por isso, o projeto usa `HKDF` para derivar chaves de sessao e chaves de mensagem adequadas.

### 9.4. `AES-GCM`

`AES-GCM` e uma cifra autenticada. Foi escolhida por fornecer confidencialidade e integridade numa unica primitiva, evitando a necessidade de construir manualmente uma composicao entre cifra e MAC.

### 9.5. `PBKDF2HMAC-SHA256`

Foi usado para proteger perfis locais a partir de passwords. A utilizacao de `salt` e iteracoes torna ataques de dicionario mais caros do que se a password fosse usada diretamente como chave.

### 9.6. Certificados X.509

Os certificados ligam identidades a chaves publicas. Esta ligacao e essencial para evitar ataques em que um adversario substitui uma chave publica legitima por outra controlada por si.

---


## 10. Testes e Validacao

### 10.1. Testes automaticos

Foram executados os testes de integracao:

```bash
python3 -m unittest tests.test_integration -v
```

Os testes cobrem:

- criacao de perfis;
- registo de utilizadores;
- emissao e validacao de certificados;
- autenticacao cliente-servidor;
- envio offline;
- rececao e decifragem;
- confirmacao com `ack`;
- remocao de one-time prekey;
- rejeicao de envelopes com metadata inconsistente;
- demonstracao pratica da forward secrecy.

Resultado obtido:

```text
Ran 2 tests
OK
```

### 10.2. Teste por TCP real

Foi tambem realizado um teste manual/automatizado com sockets TCP reais, cobrindo:

- arranque do servidor;
- criacao de perfis para Alice e Bob;
- registo dos dois utilizadores;
- adicao de Bob como contacto de Alice;
- envio de mensagem offline;
- armazenamento no servidor;
- rececao por Bob;
- confirmacao da mensagem;
- verificacao de que o plaintext nao aparece em `server.db`.

Este teste confirmou que o sistema funciona fora do ambiente simulado dos testes unitarios.

### 10.3. Testes negativos

Foram ainda verificados cenarios de erro:

- password errada no perfil e rejeitada;
- registo duplicado com chaves diferentes e rejeitado;
- envelope adulterado e rejeitado.

Estes testes ajudam a validar que as verificacoes criptograficas falham de forma segura.

---

## 11. Limitacoes e Melhorias Futuras

### 11.1. Limitacoes conhecidas

A solucao nao implementa:

- revogacao de certificados;
- rotacao automatica de certificados;
- multi-dispositivo;
- mensagens de grupo;
- modo descentralizado;
- double ratchet completo;
- post-compromise security;
- ocultacao de metadados.

O servidor continua a observar remetente, destinatario, timestamps e tamanho aproximado dos envelopes. Esta limitacao e inerente a arquitetura cliente-servidor implementada.

### 11.2. Consumo prematuro de one-time prekeys

Quando um emissor pede um delivery bundle, o servidor remove uma one-time prekey da pool do destinatario. Se o emissor nao enviar a mensagem, essa one-time prekey fica perdida.

Esta situacao nao compromete diretamente a confidencialidade, mas pode afetar a disponibilidade, pois permite esgotar prekeys mais rapidamente.

### 11.3. Melhorias futuras

Como melhorias futuras, poderiam ser implementadas:

1. Revogacao de certificados atraves de CRL ou mecanismo equivalente;
2. Rotacao periodica de signed prekeys e certificados;
3. Suporte multi-dispositivo;
4. Mensagens de grupo com gestao de chaves de grupo;
5. Double ratchet para post-compromise security;
6. Reducao de metadados visiveis ao servidor;
7. Recibos de entrega assinados;
8. Mecanismo de reposicao mais robusto de one-time prekeys.

---

## 12. Conclusao

O sistema desenvolvido cumpre o objetivo principal do enunciado: implementar um chat seguro cliente-servidor com mensagens protegidas por end-to-end encryption. A solucao garante confidencialidade, integridade e autenticidade, tanto no canal cliente-servidor como no conteudo das mensagens entre utilizadores.

A implementacao usa primitivas modernas e alinhadas com a materia da unidade curricular: `X25519`, `Ed25519`, `HKDF`, `AES-GCM`, `PBKDF2HMAC` e certificados X.509. A gestao de identidades foi reforcada com uma PKI local, e a entrega assincrona foi suportada atraves de mensagens offline.

As tres valorizacoes escolhidas foram implementadas de forma coerente:

- PKI com CA local;
- mensagens offline com armazenamento opaco no servidor;
- forward secrecy pratica atraves de signed prekeys e one-time prekeys.

Embora existam limitacoes assumidas, como a ausencia de revogacao de certificados, grupos e double ratchet completo, estas nao comprometem os objetivos centrais do trabalho. A solucao final apresenta uma arquitetura clara, testada e fundamentada nos conceitos estudados na unidade curricular.