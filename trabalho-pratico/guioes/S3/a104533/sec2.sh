#!/bin/bash

MEMBRO1="a104533"
MEMBRO2="a104355"
MEMBRO3="a104266"
BASE_DIR="$(pwd)"

# Exercicio 0
cat /etc/passwd
cat /etc/group

# Exercicio 1
sudo adduser "$MEMBRO1"
sudo adduser "$MEMBRO2"
sudo adduser "$MEMBRO3"

# Exercicio 2
sudo groupadd grupo-ssi
sudo groupadd par-ssi

sudo usermod -aG grupo-ssi "$MEMBRO1"
sudo usermod -aG grupo-ssi "$MEMBRO2"
sudo usermod -aG grupo-ssi "$MEMBRO3"

sudo usermod -aG par-ssi "$MEMBRO1"
sudo usermod -aG par-ssi "$MEMBRO2"

# Exercicio 3
cat /etc/passwd
cat /etc/group
# Comentario: novas entradas em /etc/passwd para a104533, a104355 e a104266.
# aparecem os grupos grupo-ssi e par-ssi em /etc/group, com membros corretos.

# Exercicio 4
sudo chown "$MEMBRO1":"$MEMBRO1" "$BASE_DIR/braga.txt"

# Exercicio 5
cat "$BASE_DIR/braga.txt"
# Comentario : deu "Permission denied" para core.
# braga.txt estava com permissao 400 e o dono foi mudado para a104533.

# Exercicio 6
sudo -iu "$MEMBRO1" bash -c 'echo "Sessao iniciada como: $(whoami)"'

# Exercicio 7
sudo -iu "$MEMBRO1" bash -c 'id; groups'
# Comentario: id mostrou uid/gid de a104533 e grupos a104533, users, grupo-ssi e par-ssi.
# "id" mostra UID/GID e grupos; "groups" lista os grupos do utilizador atual.

# Exercicio 8
sudo -iu "$MEMBRO1" bash -c "cat '$BASE_DIR/braga.txt'"
# Comentario: como a104533 (novo dono), a leitura funcionou e foi mostrado o conteudo "Braga".

# Exercicio 9
sudo -iu "$MEMBRO1" bash -c "cd '$BASE_DIR/dir2' && pwd"
# Comentario: deu "Permission denied" ao entrar em dir2.
# em sec1, dir2 ficou sem permissao de execucao para group/other, logo este utilizador nao consegue fazer cd.
