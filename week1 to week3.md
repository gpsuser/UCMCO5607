# Week1 to Week3

## Videos

install Virtual Box
<https://youtu.be/c0gPkwlw25A>

import fedora vm
<https://youtu.be/evFTF_nnLAY>

assembly workshop 1 part 1
<https://youtu.be/NKYU8V3I-a0>


assembly workshop 1 part 2   13min
<https://youtu.be/xV6iHhQy3yQ>


assembly workshop 2 part 1
<https://youtu.be/xV6iHhQy3yQ>


assembly workshop 2 part 2   27min
<https://youtu.be/Qrnc7GcIxto>

assembly workshop 3   36mins
<https://youtu.be/2nKgZxIPDWc>


## UKTT-Assembly 2024-25

Assembly language sessions:

UKTT stands for Underpinning Knowledge, Tools and Techniques. This is a sequential 6 lessons between DF and EH over the first 3 weeks where we introduce you to all things low level, assembly and machine code.

UoC Students only (UCM check your timetable)

## Tue Oct 1st 2024

Week 1 Lesson 1 – EthHack – Intro to UKTT

Week 1 Lesson 2 – DigiFor

## Tue Oct 8th 2024

Week 2 Lesson 3 – EthHack

Week 2 Lesson 4 – DigiFor

## Tue Oct 15th 2024

Week 3 Lesson 5 – EthHack

Week 3 Lesson 6 – DigiFor – Ending of UKTT

Week 4 onwards

We separate into the individual modules core content.

    New topics covered in the L5 UKTT (Underpinning Knowledge Tools & Techniques):
      ・  CPU machine code execution (computation) model
      ・  Assembly: x86 & x86_64 (AMD64)
      ・  System Calls
      ・  The Call Stack
      ・  Functions and Function Calls
      ・  Linking and Library Calls

    Practice: Small Assembly programs will be constructed.

    CO5606-CO5607 Common Base (UKTT-Assembly)

## UKTT Lesson 1 (EH)

    Goals:

    1. Introduction to the EH module, introduction to UKTT, and intro to teacher. Then intro to you, what you want to gain from the module, any previous experience in EH.

    2. Check everyone is setup with the Fedora Virtual Machine. For those struggling, the teacher will provide help in class.

    3. Introduction to Evan's Debugger, and GDB.

    4. `Depending on time`: Core Architecture presentation. What is Machine Code and Assembly? How does the computer act on machine code? What are the important elements of per-instruction computation? We will continue with this in Lesson 2.

    5. Depending on time: Introduce Workshop 1.


    cs.lmu.edu/~ray/notes/ ...
    NASM Tutorial: http://cs.lmu.edu/~ray/notes/nasmtutorial/
    x86 Assembly Language Programming: http://cs.lmu.edu/~ray/notes/x86assembly/

### Plan for today (after module intro):

    Brief guide for Assembly (X86 instructions) : https://www.cs.virginia.edu/~evans/cs216/guides/x86.html#memory

    Quick review of binary, oct, hex, dec, ... [CO4224]
    Review of c to machine code [CO4611]
    Quick dive into assembly:
       What it is - one-to-one human readable/tolerable representation of machine code
       Slides explaining the semantic construction of instructions; operations and operand(s) (if any)
       Slides BRIEFLY on how machine instructions are read from memory one-by-one (simplified model) and executed
       Slides on CPU Registers
       How SysCalls works - Linux SysCall Calling Convention
       The mov and syscall instructions (64bit)
       Try coding some from the 'Workshop' (exit.s, write.s)
       Some more instructions (briefly)
    Slides (more detail) on Fetch-Decode-Execute-* Pipeline/Cycle
    Review of mem model [CO4611] - every byte has an addr

    ...Whatever we don't finish, we will continue on in the next class ('Lesson 2', later).
  

    24-25 - Introduction to the Ethical Hacking module (PPTX)
    
    
    24-25 - Introduction to the Ethical Hacking module (PDF)
  
    CO5607 Module Overview
   
    UKTT Lesson 1 - Core Architecture Registers and System Call
    
    Word size and x86 WORD, DWORD, and QWORD
    
    CPU Registers and Word Size (QUICK LOOK)
   
    Lesson 1 - x86 Syntax - ATT vs Intel
   
    Workshop 1 - Beginning x86_64 Assembly (Linux)
    
    Assembly code: write64.s
   
    Assembly code: exit64.s
    

    (The NASM Manual: https://www.nasm.us/doc/)

    Input the 'exit' assembly program and save to a file ending in .s. Assemble the code, link it, then run it:

```bash

        $ nasm  -f elf64  -o exit64.o  exit64.s
        $ ld  -o exit64  exit64.o
        $ ./exit64    ← run it!
```

    Get the return value the last-run program passes back to the shell environment:

```bash
    $ ./prog    ← run the program
    $ echo $?    ← print the return value
```

    The instructions we will be exploring today and over the coming workshops on Assembly...

###    Assembly Instructions Category 	Instructions 	Covered?

    Movement 	mov, xchg   mov: Day 1
                            xchg: Day -
    Stack 	push, pop    	Day 4
    Maths 	add, sub, mul, div, inc, dec  	add: Day 1
                                            others: Day -
    Logic 	and, or, not, xor
    	
    Shiftiness 	shl, shr, rol, ror
    	
    Conditions 	jl, jg, je, jne, jmp, cmp  	Day 2
    Subroutines 	call, ret           	Day 2
    Randomness 	rdrand 	
    No Operation 	nop 	
    Syscall 	int, syscall     	syscall: Day 1

    We will assemble programs using the nasm tool at the command line, and then link the object code using ld:

    For 64 bit programs (native on our 64 bit platform)...
        $ nasm  -f elf64  -o object_file.o  source_file.s
        $ ld  -o executable_file  object_file.o

    For 32 bit programs (on our 64 bit platform)...
        $ nasm  -f elf32  -o object_file.o  source_file.s
        $ ld  -m elf_i386  -o executable_file  object_file.o

## UKTT Lesson 2

    Goals:

    1. Intro to DF module.

    2. Complete Core Architecture.

    3. Review Workshop 1.

    4. New Material for today: Digging deeper with assembly / machine code instructions, and practising with the debugger - stepping through execution.

    5. Introduce Workshop 2.
    
    UKTT Lesson 2 - Core: Conditionals, loops, debugging, intro to function calling conventions
   
    Workshop 2 - Looping and Function Calls
    475.2 KB

### Plan for today 

    Review lesson 1 and make sure the VM working for everyone.

    Instructions: Operators and Operands
    Evans Debugger (edb) practise
    Loops – Theory

    Workshop 2 – Loops:
       1. Write a loop
       2. Step in edb
       3. Make it do a write Hello World inline 5 times
       4. Put the write into a function
    Function calling conventions on x86_64 Linux

## UKTT Lesson 3

    More debugging (with EDB).

    Day 3 Core: Function Calling Conventions (Linux, 64 bit) including Theory, More coding and more debugging. (see core content below)

    Plan for today

    Workshop 1 - A simple print on screen using syscall

    Workshop 2 – loops, stepping execution in debugger, Hello World × 10, funcs (from last class)

    Workshop 3 - Print on screen using Printf function 

    gcc file.o -m32 -o exe-file 

    Function calling conventions on x86_64 Linux
       Theory
       More coding
       More debugging


    Day 3 - Function Calling Conventions (Linux, 64 bit)
 
    Workshop 1 solution


    Workshop 2 solution

    Workshop 3 - Coding Challenges 1 (x86_64 Linux)

    functiondemo.s

    OLD: Core: Conditionals Explained and the 64 bit Function Calling Convention


## UKTT Lesson 4

Exploring 32bit (i386) instructions, 32 bit Linux syscall convention, and 32 bit function calling convention.  The Call Stack.

Stack frame explanation: Buffer Overflow Attack Lecture (Part 1) [VIDEO] 

Day3: Workshop3 solution

UKTT-Assembly W2-2 - Exploring 32bit Assembly (i386)

Assembly code: exit32.s

Assembly code: write32.s

C code: average.c

Workshop 4 - Function Calling

## UKTT Lesson 5

Libraries - Linking, Loading, and Calling.  More on the Call Stack.  Inventive ways to execute code (e.g. return oriented, self-writing, JIT).



Workshop 5 - Library Calling

Libraries and Code Execution Ways
1.2 MB

## UKTT Lesson 6

UKTT-Assembly: Wrap up, workshops and going forward.


Video icon
skeleton.asm walkthrough
<https://moodle.chester.ac.uk/mod/url/view.php?id=440236>

Walkthrough of the skeleton.asm program we are using for the wrap-up.
