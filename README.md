# UCMCO5607 - Ethical Hacking

Shared folder location
<C:\work\forensics>

## First Assembly Program

```assembly
section .text

global _start
_start:
  mov rax, 60       ; the exit() call number
  mov rdi, 5        ;   // something to look at
  syscall           ; make the call
```

## Description of first Assembly program

section .text
Code lives in text section of the assembler file

section .data
Data would live in the data section of the file


global _start
This is the label that defines where the program starts

_start
This is where the program goes to to start

mov rax, 60
Moves the value 60 to the rax register

mov rdi, 5
Moves the value 5 to the rdi register

syscall
USE THIS WEBSITE: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

Go to the rax column and find 60 - which shows "sys_exit"
sys_exit arguments are in the columns on the right
sys_exit takes one

Note: you pass in the arguments through  registers
For 60 you have to pass in the argument %rdi which is the error code we want to return back to whatever  back to whatever called this
So 5 is what we are going to return to the operating system 

The syscall will look at the two registers 
It will see that rax has 60 

### Running the program

Use `nasm` the assembly compiler to compile the program.

```bash
[cyber@cyberbox ~]$ nasm -f elf64 -o exit64.o exit64.s
```

Use `ld` the linker to link the object file to an executable.

```bash
[cyber@cyberbox ~]$ ld -o exit64 exit64.o
```

Run the program.

```bash
[cyber@cyberbox ~]$ ./exit64
```

Check the exit code.

```bash
[cyber@cyberbox ~]$ echo $?
5
```

Therefore last run program was exited with the exit  code 5.

If we run another command:
    
```bash
[cyber@cyberbox ~]$ echo hello
```
    
Then check the exit code.

```bash
[cyber@cyberbox ~]$ echo $?
0
```

So the last run program has an exit code of 0 which means it ran successfully.

NOTE: You can go bak into the original assembly code and shnge teh return code from 5 to 0 and recompile and relink and rerun the program and you will see that the exit code will be 0.

### Comments in assembly

Comments in assembly are denoted by a semi-colon `;`

```assembly
; This is a comment
```

REturn codes are important because teh OS may need to know if our program has run successfully or not - however other calling programs may also need to know if our program has run successfully or not.

### Using EDB

You can use EDB to debug the program.

cd to the directory where the program is located and run the following command:

```bash
cd /home/cyber/soft/edb-build/
./edb
```

Then open the program and open our first assembler program that we have just written.

file location:

```bash
/media/sf_forensics/workshop1/exit64
```

Note that exit64 is actuallly the executable file that we created.

Minimise the edb output screen and change the font size Options> references > Appearance > DEfault register view font > 8

EDB disassembles the program and shows the assembly code.

video 1 18:15
