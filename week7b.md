# Week 7b - Buffer Overflow Vulnerabilities

We will complete the memory model of a program and complete the stack analysis of 32 and 64 bit systems. We will also cover buffer and stack overflow vulnerabilities. We will write multiple C programs to understand the stack and buffer overflow vulnerabilities. Each program will be analysed in GDB debugger.

## Useful resources

Tutorial on 32 bit Assembly: <https://www.tutorialspoint.com/assembly_programming/assembly_system_calls.htm>

Set up user friendly gdb with GEF: 

```bash
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

## A simple program with buffer overflow vulnerability

```bash
[cyber@cyberbox ~]$ cd /media/sf_forensics/week7b/

[cyber@cyberbox week7b]$ ls -lha
total 8.0K
drwxrwx---. 1 root vboxsf    0 Nov 28 22:01 .
drwxrwx---. 1 root vboxsf 4.0K Nov 28 22:00 ..
-rwxrwx---. 1 root vboxsf  857 Nov 28 22:01 buffer_overflow_global.c

[cyber@cyberbox week7b]$ gcc -m32 buffer_overflow_global.c -o buffer_overflow_global -g -O0

```


```c
// buffer_overflow_global.c

#include <stdio.h>
#include <string.h>

// Global variables:
char bufferr[16];   // declare space to hold a string of characters
int  my_number;    // declare space to hold a set value


int main(int argc, char* argv[])
{
	// Program starts here.

	my_number = 10;                // set my_number to 10


	if (argc > 1)
	{
	    strcpy(bufferr, argv[1]);   // string copy ( destination, source )

	    printf("my_number is: ");  //
	    printf("%d", my_number);   // print decimal value of my_number 
	    printf("\n");              // 'End of line' / 'Newline' character

	}
	else
	{
	    printf("######################################\n");
	    printf("### Program requires one argument. ###\n");
	    printf("### Usage:   progname <a-string>   ###\n");
	    printf("######################################\n");
	}
	
	return 0;
}
```
run gdb and set break points

```bash
[cyber@cyberbox week7b]$ gdb ./bog

gef➤  break strcpy
Breakpoint 1 at 0x8049060
gef➤  break printf
Breakpoint 2 at 0x8049050
gef➤  run "testing"

Starting program: /media/sf_forensics/week7b/bog "testing"

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.fedoraproject.org/>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Breakpoint 1, __GI_strcpy (dest=0x804c01c <bufferr> "", src=0xffffd2e2 "testing") at strcpy.c:30
30	{

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd2e2  →  "testing"
$ebx   : 0xf7fa4ff4  →  0x001e7d8c
$ecx   : 0xffffd040  →  0x00000002
$edx   : 0xffffd060  →  0xf7fa4ff4  →  0x001e7d8c
$esp   : 0xffffd00c  →  0x080491de  →  <main+0038> add esp, 0x10
$ebp   : 0xffffd028  →  0x00000000
$esi   : 0xffffd100  →  0xffffd2ea  →  "IMSETTINGS_INTEGRATE_DESKTOP=yes"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xf7e616e0  →  <strcpy+0000> endbr32 
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd00c│+0x0000: 0x080491de  →  <main+0038> add esp, 0x10	 ← $esp
0xffffd010│+0x0004: 0x0804c01c  →  <bufferr+0000> add BYTE PTR [eax], al
0xffffd014│+0x0008: 0xffffd2e2  →  "testing"
0xffffd018│+0x000c: 0xf7fc1390  →  0xf7dbd000  →  0x464c457f
0xffffd01c│+0x0010: 0x00000000
0xffffd020│+0x0014: 0x00000000
0xffffd024│+0x0018: 0xffffd040  →  0x00000002
0xffffd028│+0x001c: 0x00000000	 ← $ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e616d8 <strcoll_l+0ff8> call   0xf7def4a0 <__libc_assert_fail>
   0xf7e616dd <annobin_strcoll_l.c_end+0000> xchg   ax, ax
   0xf7e616df <annobin_strcoll_l.c_end+0002> nop    
●→ 0xf7e616e0 <strcpy+0000>    endbr32 
   0xf7e616e4 <strcpy+0004>    push   esi
   0xf7e616e5 <strcpy+0005>    call   0xf7f1d539 <__x86.get_pc_thunk.si>
   0xf7e616ea <strcpy+000a>    add    esi, 0x14390a
   0xf7e616f0 <strcpy+0010>    push   ebx
   0xf7e616f1 <strcpy+0011>    sub    esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────── source:strcpy.c+30 ────
     25	 #endif
     26	 
     27	 /* Copy SRC to DEST.  */
     28	 char *
     29	 STRCPY (char *dest, const char *src)
 →   30	 {
     31	   return memcpy (dest, src, strlen (src) + 1);
     32	 }
     33	 libc_hidden_builtin_def (strcpy)
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "bog", stopped 0xf7e616e0 in __GI_strcpy (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e616e0 → __GI_strcpy(dest=0x804c01c <bufferr> "", src=0xffffd2e2 "testing")
[#1] 0x80491de → main(argc=0x2, argv=0xffffd0f4)
───────





gef➤  continue
Continuing.

Breakpoint 2, __printf (format=0x804a00c "my_number is: ") at printf.c:28
28	{

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804c01c  →  "testing"
$ebx   : 0xf7fa4ff4  →  0x001e7d8c
$ecx   : 0x0       
$edx   : 0xf7fa4ff4  →  0x001e7d8c
$esp   : 0xffffd00c  →  0x080491ee  →  <main+0048> add esp, 0x10
$ebp   : 0xffffd028  →  0x00000000
$esi   : 0xffffd100  →  0xffffd2ea  →  "IMSETTINGS_INTEGRATE_DESKTOP=yes"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xf7e13400  →  <printf+0000> endbr32 
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd00c│+0x0000: 0x080491ee  →  <main+0048> add esp, 0x10	 ← $esp
0xffffd010│+0x0004: 0x0804a00c  →  "my_number is: "
0xffffd014│+0x0008: 0xffffd2e2  →  "testing"
0xffffd018│+0x000c: 0xf7fc1390  →  0xf7dbd000  →  0x464c457f
0xffffd01c│+0x0010: 0x00000000
0xffffd020│+0x0014: 0x00000000
0xffffd024│+0x0018: 0xffffd040  →  0x00000002
0xffffd028│+0x001c: 0x00000000	 ← $ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e133f7 <perror+00d7>    add    esp, 0x10
   0xf7e133fa <perror+00da>    jmp    0xf7e1335c <__GI_perror+60>
   0xf7e133ff <annobin_perror.c_end+0000> nop    
●→ 0xf7e13400 <printf+0000>    endbr32 
   0xf7e13404 <printf+0004>    call   0xf7f1d531 <__x86.get_pc_thunk.ax>
   0xf7e13409 <printf+0009>    add    eax, 0x191beb
   0xf7e1340e <printf+000e>    sub    esp, 0xc
   0xf7e13411 <printf+0011>    lea    edx, [esp+0x14]
   0xf7e13415 <printf+0015>    push   0x0
────────────────────────────────────────────────────────────────────────────────────────────────── source:printf.c+28 ────
     23	 
     24	 /* Write formatted output to stdout from the format string FORMAT.  */
     25	 /* VARARGS1 */
     26	 int
     27	 __printf (const char *format, ...)
 →   28	 {
     29	   va_list arg;
     30	   int done;
     31	 
     32	   va_start (arg, format);
     33	   done = __vfprintf_internal (stdout, format, arg, 0);
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "bog", stopped 0xf7e13400 in __printf (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e13400 → __printf(format=0x804a00c "my_number is: ")
[#1] 0x80491ee → main(argc=0x2, argv=0xffffd0f4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤

gef➤  continue
Continuing.

Breakpoint 2, __printf (format=0x804a01b "%d") at printf.c:28
28	{

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xa       
$ebx   : 0xf7fa4ff4  →  0x001e7d8c
$ecx   : 0x0       
$edx   : 0x0       
$esp   : 0xffffd00c  →  0x08049204  →  <main+005e> add esp, 0x10
$ebp   : 0xffffd028  →  0x00000000
$esi   : 0xffffd100  →  0xffffd2ea  →  "IMSETTINGS_INTEGRATE_DESKTOP=yes"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xf7e13400  →  <printf+0000> endbr32 
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd00c│+0x0000: 0x08049204  →  <main+005e> add esp, 0x10	 ← $esp
0xffffd010│+0x0004: 0x0804a01b  →  0x00006425 ("%d"?)
0xffffd014│+0x0008: 0x0000000a ("\n"?)
0xffffd018│+0x000c: 0xf7fc1390  →  0xf7dbd000  →  0x464c457f
0xffffd01c│+0x0010: 0x00000000
0xffffd020│+0x0014: 0x00000000
0xffffd024│+0x0018: 0xffffd040  →  0x00000002
0xffffd028│+0x001c: 0x00000000	 ← $ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e133f7 <perror+00d7>    add    esp, 0x10
   0xf7e133fa <perror+00da>    jmp    0xf7e1335c <__GI_perror+60>
   0xf7e133ff <annobin_perror.c_end+0000> nop    
●→ 0xf7e13400 <printf+0000>    endbr32 
   0xf7e13404 <printf+0004>    call   0xf7f1d531 <__x86.get_pc_thunk.ax>
   0xf7e13409 <printf+0009>    add    eax, 0x191beb
   0xf7e1340e <printf+000e>    sub    esp, 0xc
   0xf7e13411 <printf+0011>    lea    edx, [esp+0x14]
   0xf7e13415 <printf+0015>    push   0x0
────────────────────────────────────────────────────────────────────────────────────────────────── source:printf.c+28 ────
     23	 
     24	 /* Write formatted output to stdout from the format string FORMAT.  */
     25	 /* VARARGS1 */
     26	 int
     27	 __printf (const char *format, ...)
 →   28	 {
     29	   va_list arg;
     30	   int done;
     31	 
     32	   va_start (arg, format);
     33	   done = __vfprintf_internal (stdout, format, arg, 0);
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "bog", stopped 0xf7e13400 in __printf (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e13400 → __printf(format=0x804a01b "%d")
[#1] 0x8049204 → main(argc=0x2, argv=0xffffd0f4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  


Continuing.
my_number is: 10
[Inferior 1 (process 3940) exited normally]
gef➤
```

## Change the input string so that it is longer than the buffer size (use same breakpoints)

```bash
gef➤  run 'AAAAAAAAAAAAAAAAA\x01\x02\'


gef➤  run 'AAAAAAAAAAAAAAAAA\x01\x02\'
Starting program: /media/sf_forensics/week7b/bog 'AAAAAAAAAAAAAAAAA\x01\x02\'

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.fedoraproject.org/>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Breakpoint 1, __GI_strcpy (dest=0x804c01c <bufferr> "", src=0xffffd2cf 'A' <repeats 17 times>, "\\x01\\x02\\")
    at strcpy.c:30
30	{

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd2cf  →  0x41414141 ("AAAA"?)
$ebx   : 0xf7fa4ff4  →  0x001e7d8c
$ecx   : 0xffffd030  →  0x00000002
$edx   : 0xffffd050  →  0xf7fa4ff4  →  0x001e7d8c
$esp   : 0xffffcffc  →  0x080491de  →  <main+0038> add esp, 0x10
$ebp   : 0xffffd018  →  0x00000000
$esi   : 0xffffd0f0  →  0xffffd2ea  →  "IMSETTINGS_INTEGRATE_DESKTOP=yes"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xf7e616e0  →  <strcpy+0000> endbr32 
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcffc│+0x0000: 0x080491de  →  <main+0038> add esp, 0x10	 ← $esp
0xffffd000│+0x0004: 0x0804c01c  →  <bufferr+0000> add BYTE PTR [eax], al
0xffffd004│+0x0008: 0xffffd2cf  →  0x41414141
0xffffd008│+0x000c: 0xf7fc1390  →  0xf7dbd000  →  0x464c457f
0xffffd00c│+0x0010: 0x00000000
0xffffd010│+0x0014: 0x00000000
0xffffd014│+0x0018: 0xffffd030  →  0x00000002
0xffffd018│+0x001c: 0x00000000	 ← $ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e616d8 <strcoll_l+0ff8> call   0xf7def4a0 <__libc_assert_fail>
   0xf7e616dd <annobin_strcoll_l.c_end+0000> xchg   ax, ax
   0xf7e616df <annobin_strcoll_l.c_end+0002> nop    
●→ 0xf7e616e0 <strcpy+0000>    endbr32 
   0xf7e616e4 <strcpy+0004>    push   esi
   0xf7e616e5 <strcpy+0005>    call   0xf7f1d539 <__x86.get_pc_thunk.si>
   0xf7e616ea <strcpy+000a>    add    esi, 0x14390a
   0xf7e616f0 <strcpy+0010>    push   ebx
   0xf7e616f1 <strcpy+0011>    sub    esp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────── source:strcpy.c+30 ────
     25	 #endif
     26	 
     27	 /* Copy SRC to DEST.  */
     28	 char *
     29	 STRCPY (char *dest, const char *src)
 →   30	 {
     31	   return memcpy (dest, src, strlen (src) + 1);
     32	 }
     33	 libc_hidden_builtin_def (strcpy)
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "bog", stopped 0xf7e616e0 in __GI_strcpy (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e616e0 → __GI_strcpy(dest=0x804c01c <bufferr> "", src=0xffffd2cf 'A' <repeats 17 times>, "\\x01\\x02\\")
[#1] 0x80491de → main(argc=0x2, argv=0xffffd0e4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  

gef➤  continue
Continuing.

Breakpoint 2, __printf (format=0x804a00c "my_number is: ") at printf.c:28
28	{

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804c01c  →  <bufferr+0000> inc ecx
$ebx   : 0xf7fa4ff4  →  0x001e7d8c
$ecx   : 0x0       
$edx   : 0xf7fa4ff4  →  0x001e7d8c
$esp   : 0xffffcffc  →  0x080491ee  →  <main+0048> add esp, 0x10
$ebp   : 0xffffd018  →  0x00000000
$esi   : 0xffffd0f0  →  0xffffd2ea  →  "IMSETTINGS_INTEGRATE_DESKTOP=yes"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xf7e13400  →  <printf+0000> endbr32 
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcffc│+0x0000: 0x080491ee  →  <main+0048> add esp, 0x10	 ← $esp
0xffffd000│+0x0004: 0x0804a00c  →  "my_number is: "
0xffffd004│+0x0008: 0xffffd2cf  →  0x41414141
0xffffd008│+0x000c: 0xf7fc1390  →  0xf7dbd000  →  0x464c457f
0xffffd00c│+0x0010: 0x00000000
0xffffd010│+0x0014: 0x00000000
0xffffd014│+0x0018: 0xffffd030  →  0x00000002
0xffffd018│+0x001c: 0x00000000	 ← $ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e133f7 <perror+00d7>    add    esp, 0x10
   0xf7e133fa <perror+00da>    jmp    0xf7e1335c <__GI_perror+60>
   0xf7e133ff <annobin_perror.c_end+0000> nop    
●→ 0xf7e13400 <printf+0000>    endbr32 
   0xf7e13404 <printf+0004>    call   0xf7f1d531 <__x86.get_pc_thunk.ax>
   0xf7e13409 <printf+0009>    add    eax, 0x191beb
   0xf7e1340e <printf+000e>    sub    esp, 0xc
   0xf7e13411 <printf+0011>    lea    edx, [esp+0x14]
   0xf7e13415 <printf+0015>    push   0x0
────────────────────────────────────────────────────────────────────────────────────────────────── source:printf.c+28 ────
     23	 
     24	 /* Write formatted output to stdout from the format string FORMAT.  */
     25	 /* VARARGS1 */
     26	 int
     27	 __printf (const char *format, ...)
 →   28	 {
     29	   va_list arg;
     30	   int done;
     31	 
     32	   va_start (arg, format);
     33	   done = __vfprintf_internal (stdout, format, arg, 0);
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "bog", stopped 0xf7e13400 in __printf (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e13400 → __printf(format=0x804a00c "my_number is: ")
[#1] 0x80491ee → main(argc=0x2, argv=0xffffd0e4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 


ef➤  continue
Continuing.

Breakpoint 2, __printf (format=0x804a01b "%d") at printf.c:28
28	{

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x30785c41 ("A\x0"?)
$ebx   : 0xf7fa4ff4  →  0x001e7d8c
$ecx   : 0x0       
$edx   : 0x0       
$esp   : 0xffffcffc  →  0x08049204  →  <main+005e> add esp, 0x10
$ebp   : 0xffffd018  →  0x00000000
$esi   : 0xffffd0f0  →  0xffffd2ea  →  "IMSETTINGS_INTEGRATE_DESKTOP=yes"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0xf7e13400  →  <printf+0000> endbr32 
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcffc│+0x0000: 0x08049204  →  <main+005e> add esp, 0x10	 ← $esp
0xffffd000│+0x0004: 0x0804a01b  →  0x00006425 ("%d"?)
0xffffd004│+0x0008: 0x30785c41
0xffffd008│+0x000c: 0xf7fc1390  →  0xf7dbd000  →  0x464c457f
0xffffd00c│+0x0010: 0x00000000
0xffffd010│+0x0014: 0x00000000
0xffffd014│+0x0018: 0xffffd030  →  0x00000002
0xffffd018│+0x001c: 0x00000000	 ← $ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e133f7 <perror+00d7>    add    esp, 0x10
   0xf7e133fa <perror+00da>    jmp    0xf7e1335c <__GI_perror+60>
   0xf7e133ff <annobin_perror.c_end+0000> nop    
●→ 0xf7e13400 <printf+0000>    endbr32 
   0xf7e13404 <printf+0004>    call   0xf7f1d531 <__x86.get_pc_thunk.ax>
   0xf7e13409 <printf+0009>    add    eax, 0x191beb
   0xf7e1340e <printf+000e>    sub    esp, 0xc
   0xf7e13411 <printf+0011>    lea    edx, [esp+0x14]
   0xf7e13415 <printf+0015>    push   0x0
────────────────────────────────────────────────────────────────────────────────────────────────── source:printf.c+28 ────
     23	 
     24	 /* Write formatted output to stdout from the format string FORMAT.  */
     25	 /* VARARGS1 */
     26	 int
     27	 __printf (const char *format, ...)
 →   28	 {
     29	   va_list arg;
     30	   int done;
     31	 
     32	   va_start (arg, format);
     33	   done = __vfprintf_internal (stdout, format, arg, 0);
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "bog", stopped 0xf7e13400 in __printf (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e13400 → __printf(format=0x804a01b "%d")
[#1] 0x8049204 → main(argc=0x2, argv=0xffffd0e4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  


gef➤  continue
Continuing.
my_number is: 813194305
[Inferior 1 (process 4002) exited normally]
gef➤  
















```

### Working with breakpoints

To delete breakpoints, use the `delete` command followed by the breakpoint number. For example, to delete breakpoint 1, you can use the following command:

```bash
(gdb) delete 1
```
alternatively you can delete all breakpoints using the `delete` command followed by the keyword `breakpoints`. For example, to delete all breakpoints, you can use the following command:

```bash
delete breakpoints
```

To findout the address of a function, use the `info address` command followed by the function name. For example, to find the address of the `main` function, you can use the following command:

```bash
(gdb) info address main
```
To find information about the stack, use the `info frame` command. For example, to find information about the current stack frame, you can use the following command:

```bash
(gdb) info frame
```
To find information about the registers, use the `info registers` command. For example, to find information about the registers, you can use the following command:

```bash
(gdb) info registers
```
To find information about the memory, use the `x` command followed by the memory address. For example, to find information about the memory at address `0x7fffffffe0c0`, you can use the following command:

```bash
(gdb) x /4xb 0x7fffffffe0c0
```
In the above command,
```x``` is the command to examine memory. ```/4``` specifies the number of units to display. ```xb``` specifies the format to display the memory in. In this case, ```xb``` displays the memory in hexadecimal format.

to run the program in gdb

```bash
(gdb) run
```

to set a break point at the main function

```bash
(gdb) break main
```

to set a break point at the helper function

```bash
(gdb) break helper_function
```
to find out information about break points

```bash
(gdb) info break


To continue running the program, use the `continue` command. For example, to continue running the program, you can use the following command:

```bash
(gdb) continue
```
To quit GDB, use the `quit` command. For example, to quit GDB, you can use the following command:

```bash

(gdb) quit
```


```







## Workshop 1 - Buffer Overflow

### Objective

To understand the concept of buffer overflow and how it can be exploited.

### Instructions

1. Write a simple C program that has a buffer overflow vulnerability.
2. Compile the program with debugging information.
3. Run the program in GDB and demonstrate the buffer overflow vulnerability.
4. Explain how the buffer overflow can be exploited to execute arbitrary code.

## Workshop 2 - Stack Overflow

### Objective

To understand the concept of stack overflow and how it can be exploited

### Instructions

1. Write a simple C program that has a stack overflow vulnerability.
2. Compile the program with debugging information.
3. Run the program in GDB and demonstrate the stack overflow vulnerability.
4. Explain how the stack overflow can be exploited to execute arbitrary code.

## Workshop 3 - Writing Secure Code

### Objective

To understand how to write secure code that is not vulnerable to buffer and stack overflow attacks.

### Instructions

1. Write a simple C program that is not vulnerable to buffer or stack overflow attacks.
2. Compile the program with debugging information.
3. Run the program in GDB and demonstrate that it is not vulnerable to buffer or stack overflow attacks.
4. Explain the techniques used to make the program secure.

## Workshop 4 - Exploiting Buffer Overflow

### Objective

To exploit a buffer overflow vulnerability in a C program.

### Instructions

1. Write a C program that has a buffer overflow vulnerability.
2. Compile the program with debugging information.
3. Run the program in GDB and identify the buffer overflow vulnerability.
4. Exploit
5. Explain how the buffer overflow can be exploited to execute arbitrary code.

## Workshop 5 - Exploiting Stack Overflow

### Objective

To exploit a stack overflow vulnerability in a C program.

### Instructions

1. Write a C program that has a stack overflow vulnerability.
2. Compile the program with debugging information.
3. Run the program in GDB and identify the stack overflow vulnerability.
4. Exploit
5. Explain how the stack overflow can be exploited to execute arbitrary code.

## Workshop1 - Solution

```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "Hello, World!");
    printf("%s\n", buffer);
    return 0;
}
```

```bash
gcc -g -o buffer_overflow buffer_overflow.c
gdb ./buffer_overflow
```

```bash
(gdb) run
```

## Workshop2 - Solution

```c
#include <stdio.h>

void recursive_function(int x) {
    int buffer[10];
    printf("Recursive function called with x = %d\n", x);
    recursive_function(x + 1);
}

int main() {
    recursive_function(0);
    return 0;
}
```

```bash
gcc -g -o stack_overflow stack_overflow.c
gdb ./stack_overflow
```

```bash
(gdb) run
```

## Workshop3 - Solution

```c
#include <stdio.h>

void helper_function(int x) {
    printf("Helper function called with x = %d\n", x);
}

int main() {
    int a = 5;
    int b = 10;
    helper_function(a + b);
    return 0;
}
```

```bash
gcc -g -o secure_program secure_program.c
gdb ./secure_program
```

```bash
(gdb) run
```

## Workshop4 - Solution

```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "Hello, World!");
    printf("%s\n", buffer);
    return 0;
}
```

```bash
gcc -g -o buffer_overflow buffer_overflow.c
gdb ./buffer_overflow
```

```bash
(gdb) run
```

## Workshop5 - Solution

```c
#include <stdio.h>

void recursive_function(int x) {
    int buffer[10];
    printf("Recursive function called with x = %d\n", x);
    recursive_function(x + 1);
}

int main() {
    recursive_function(0);
    return 0;
}
```

```bash
gcc -g -o stack_overflow stack_overflow.c
gdb ./stack_overflow
```

```bash
(gdb) run
```

