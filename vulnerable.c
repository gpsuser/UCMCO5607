// vulnerable.c
#include <stdio.h>
#include <string.h>

void print_name(char* name) {
    char buffer[32];
    strcpy(buffer, name);  // Vulnerable to buffer overflow
    printf("Hello, %s!\n", buffer);
}

int main(int argc, char** argv) {
    if(argc != 2) {
        printf("Usage: %s <name>\n", argv[0]);
        return 1;
    }
    print_name(argv[1]);
    return 0;
}