// vulnerable.c
#include <stdio.h>
#include <string.h>

void greet_user(char* name) {
    // Creating a buffer that's too small for potential input
    char buffer[64];
    
    // Vulnerable: No bounds checking on strcpy
    strcpy(buffer, name);
    printf("Hello, %s!\n", buffer);
}

int main(int argc, char** argv) {
    if(argc != 2) {
        printf("Usage: %s <name>\n", argv[0]);
        return 1;
    }
    greet_user(argv[1]);
    return 0;
}
