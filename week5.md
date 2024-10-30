#  Week 5 (Stack exploitation)

Today we'll continue analysing the stack. We will complete stack diagram of a program/process. We will also cover the stack overflow vulnerabilities. We will write multiple C programs to understand the stack and buffer overflow vulnerabilities. Each program will be analysed in GDB debugger.

How to disable the ASLR:

Check ASLR status

cat /proc/sys/kernel/randomize_va_space

    0 – No randomization. Everything is static.
    1 – Conservative randomization. Shared libraries, stack, mmap(), VDSO and heap are randomized.
    2 – Full randomization. In addition to elements listed in the previous point, memory managed through brk() is also randomized.

Disable the ASLR:

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space     (Make sure you have the root privileges)

