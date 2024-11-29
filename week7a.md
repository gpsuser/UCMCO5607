# Week 7 - Stack Exploitation 

SEgmentation fault is a common error that occurs when a program tries to access memory that it doesn't have permission to access. This can happen when a program tries to access memory that is outside of its address space, or when it tries to access memory that is protected by the operating system.

In this workshop, we will explore how stack overflow vulnerabilities can be exploited to gain unauthorized access to a program's memory. We will use a vulnerable program that contains a stack overflow vulnerability, and we will exploit this vulnerability to gain control of the program's execution.

The program:

```c
#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buffer[16];
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    vuln(argv[1]);

    return 0;
}
```

Normally, the `vuln` function copies the input string into a buffer of size 16. However, if the input string is longer than 16 characters, it will overflow the buffer and overwrite other memory locations on the stack.

To exploit this vulnerability, we can provide an input string that is longer than 16 characters. This will overwrite the return address of the `vuln` function on the stack, causing the program to jump to a different memory location when the function returns.

We can use this technique to redirect the program's execution to a location of our choosing, allowing us to execute arbitrary code. This is a common technique used in stack overflow attacks to gain unauthorized access to a program's memory.

In this workshop, we will demonstrate how to exploit this vulnerability and gain control of the program's execution. We will use GDB to analyze the program's memory layout and identify the location of the return address on the stack. We will then craft an input string that overwrites the return address with the address of a shellcode, allowing us to execute arbitrary code.

The goal of this workshop is to demonstrate the dangers of stack overflow vulnerabilities and the importance of secure coding practices. By understanding how these vulnerabilities can be exploited, we can better protect our programs from malicious attacks and ensure the security of our systems.


```bash
[cyber@cyberbox week7]$ gcc -g -o vuln vuln.c
[cyber@cyberbox week7]$ ./vuln "$(echo -en 'AAAAAAAAAAAAAAAAAAAA')"
Buffer: AAAAAAAAAAAAAAAA
[cyber@cyberbox week7]$ ./vuln "$(echo -en 'AAAAAAAAAAAAAAAAAAAA\x01\x02\x03\x05\xc1\x91\x04\x08')"
Buffer: AAAAAAAAAAAAAAAA
```

The first command runs the program with an input string that is exactly 16 characters long. The program executes successfully and prints the input string.

The second command runs the program with an input string that is longer than 16 characters. The program crashes with a segmentation fault, indicating that the stack has been corrupted. This is a clear sign of a stack overflow vulnerability.

In the next step, we will use GDB to analyze the program's memory layout and identify the location of the return address on the stack. We will then craft an input string that overwrites the return address with the address of a shellcode, allowing us to execute arbitrary code.

```bash
[cyber@cyberbox week7]$ gdb ./vuln
(gdb) break main
(gdb) run "$(echo -en 'AAAAAAAAAAAAAAAAAAAA\x01\x02\x03\x05\xc1\x91\x04\x08')"
(gdb) x/24x $rsp
```

The first command sets a breakpoint at the `main` function of the program. The second command runs the program with an input string that is longer than 16 characters. The third command examines the memory at the top of the stack, showing the contents of the stack frame.

By analyzing the memory layout, we can identify the location of the return address on the stack. We can then craft an input string that overwrites this address with the address of a shellcode, allowing us to execute arbitrary code.

In the final step, we will craft a shellcode that opens a shell and execute it by exploiting the stack overflow vulnerability in the program.

```bash
[cyber@cyberbox week7]$ ./vuln "$(echo -en 'AAAAAAAAAAAAAAAAAAAA\x01\x02\x03\x05\xc1\x91\x04\x08')"
Buffer: AAAAAAAAAAAAAAAA
Segmentation fault
```

The program crashes with a segmentation fault, indicating that the stack has been corrupted and the return address has been overwritten. This demonstrates how a stack overflow vulnerability can be exploited to gain unauthorized access to a program's memory and execute arbitrary code.

In conclusion, stack overflow vulnerabilities are a serious security risk that can be exploited to gain unauthorized access to a program's memory. By understanding how these vulnerabilities work and how they can be exploited, we can better protect our programs from malicious attacks



Segmentation fault

```bash
[cyber@cyberbox week7]$ ./vulnn "$(echo -en 'AAAAAAAAAAAAAAAAAAA\x01\x02\x03\x05\xc1\x91\x04\x08')"
Your input string is copied in the buffer 
Segmentation fault (core dumped)
```


Infinite Loop
```bash
[cyber@cyberbox week7]$ ./vulnn "$(echo -en 'AAAAAAAAAAAAAAAAAAAA\x01\x02\x03\x05\xc1\x91\x04\x08')"
```
The difference between the two is that the first one has an extra 'A' in the input string, which causes the buffer to overflow and overwrite the return address on the stack. This leads to a segmentation fault when the function returns, as the program tries to jump to an invalid memory location. The second input string is exactly 16 characters long, so it does not overflow the buffer and the program executes successfully.

