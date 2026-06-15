#!/bin/bash

# Ajusta este nome para um utilizador existente no grupo "grupo-ssi".
UTILIZADOR_GRUPO="a104533"

# Dependencias
sudo apt install -y acl

# Parte 1
getfacl porto.txt

# Parte 2
sudo setfacl -m g:grupo-ssi:w porto.txt

# Parte 3
getfacl porto.txt
# Comentario: surgiu a entrada ACL "group:grupo-ssi:-w-" e a respetiva mask.
# antes nao existia ACL explicita para esse grupo.

# Parte 4
sudo -u "$UTILIZADOR_GRUPO" bash -c 'echo "Texto alterado via ACL" >> porto.txt'
sudo -u "$UTILIZADOR_GRUPO" cat porto.txt
# Comentario: a escrita funcionou (ACL de escrita para o grupo-ssi), mas a leitura falhou com "Permission denied".
# foi dada permissao "w" ao grupo, nao "r"; por isso e esperado que o utilizador consigua escrever mas nao ler.
