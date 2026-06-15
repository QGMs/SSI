#!/bin/bash


# Parte 1
cat > leitor.c << 'EOF'
#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *f;
    char c;

    if (argc != 2) {
        fprintf(stderr, "Uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "r");
    if (!f) {
        perror("Erro ao abrir ficheiro");
        return 1;
    }

    while ((c = fgetc(f)) != EOF) {
        putchar(c);
    }

    fclose(f);
    return 0;
}
EOF

gcc -o leitor leitor.c
chmod +x leitor

# Parte 2
id -u userssi >/dev/null 2>&1 || sudo adduser --disabled-password --gecos "" userssi

# Parte 3
sudo chown userssi:userssi leitor braga.txt
sudo chmod 400 braga.txt

# Parte 4
./leitor braga.txt

# Parte 5
sudo chmod u+s leitor

# Parte 6
./leitor braga.txt
# Comentario: com setuid ativo, o executavel corre com o utilizador efetivo do dono (userssi) e consegue ler braga.txt.
# antes do setuid (parte4) deu "Permission denied"; depois do setuid imprimiu "Braga".
