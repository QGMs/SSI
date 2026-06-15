#!/bin/bash

# Dependencias
sudo apt install -y libcap2-bin

# Parte 1
capsh --print
# Comentario: comando listou as capabilities do processo atual (bounding set e restantes conjuntos).

# Parte 2
cat > webserver.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error when creating socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Error on bind");
        close(sockfd);
        return 1;
    }

    printf("Success: binded to port %d\n", port);
    close(sockfd);
    return 0;
}
EOF
gcc -o webserver webserver.c
chmod +x webserver

# Teste de referencia em porta nao privilegiada
./webserver 1024
# Comentario: observado "Success: binded to port 1024".

# Parte 3
./webserver 80
# Comentario: observado "Error on bind: Permission denied" na porta 80
# visto que portas inferiores a 1024 exigem privilegio (root) ou capability CAP_NET_BIND_SERVICE.

# Aplicar capability para permitir bind em portas <1024 sem setuid root.
sudo setcap cap_net_bind_service=+ep ./webserver
getcap ./webserver
./webserver 80
# Comentario: observado "cap_net_bind_service=ep" no getcap e sucesso no bind da porta 80.
