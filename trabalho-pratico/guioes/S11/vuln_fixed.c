#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret_function(void) {
    printf("\n[!] ACCESS GRANTED: you reached the secret function!\n");
    printf("[!] In a real exploit, this should not be reachable via overflow.\n\n");
    exit(0);
}

void process_input(const char *input) {
    char buffer[64];
    size_t input_len = strlen(input);

    if (input_len >= sizeof(buffer)) {
        fprintf(stderr, "[!] Input too long: max %zu bytes allowed.\n", sizeof(buffer) - 1);
        return;
    }

    memcpy(buffer, input, input_len + 1);
    printf("[*] You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    process_input(argv[1]);
    printf("[*] Normal programme termination.\n");
    return 0;
}
