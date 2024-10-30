# Week 4

## Week4 - EH Core 2024 (Buffer overflow vulnerabilities)

We will complete the memory model of a program and complete the stack analysis of 32 and 64 bit systems. We will also cover buffer and stack overflow vulnerabilities. We will write multiple C programs to understand the stack and buffer overflow vulnerabilities. Each program will be analysed in GDB debugger.


Useful resources

Tutorial on 32 bit Assembly: <https://www.tutorialspoint.com/assembly_programming/assembly_system_calls.htm>

Set up user friendly gdb with GEF:

Set up user friendly gdb with GEF:

```bash
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

 ## Week 4 - Core EH starts. Memory model and Stack function diagram

This week we will perform static and dynamic analysis of executable files on Linux.

We will also cover both Memory Model and the Stack in depth.

Static tools: objdump is a command-line program for displaying various information about object files on Unix-like operating systems.  

Example: objdump -M intel -d filename

The above command disassemble the binary file in Assembly format.

Dynamic program analysis is the analysis of computer software that is performed by executing programs on a real or virtual processor. 

GDB: The GNU Debugger is a portable debugger that runs on many Unix-like systems and works for many programming languages

User Friendly GDB configuration file:

bash -c "$(wget https://gef.blah.cat/sh -O -)"


Workshop Task 1:  Analyse the sample.c function in GDB debugger and draw a stack diagram for function1.
Compilation of simple C program: 

gcc -m32 input-file.c -o output-file

gcc -m64 input-file.c -o output-file

Change number of arguments from the C-program and analyse the changes in the assembly program.

64-bit function calling convention.
https://aaronbloomfield.github.io/pdr/book/x86-64bit-ccc-chapter.pdf

Lecture topic: Stack function diagram.

