# Using GDB


* also use: Week4_ buffer-overflow-exploitation.pdf
* week 5 functions and the stack
* No - week4 1 GDB AND Function-calling-conventions-examples

## Introduction

GDB is a powerful debugger that can be used to debug C and C++ programs. It can be used to set breakpoints, step through code, inspect variables, and more. In this workshop, we will use GDB to debug some simple C programs.

```c
// File: simple_program.c
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
gcc -g -o simple_program simple_program.c
```

```bash
gdb ./simple_program
```

## Setting Breakpoints

You can set breakpoints in GDB using the `break` command. For example, to set a breakpoint at line 8 of the program, you can use the following command:

```bash
break 8
```

You can also set breakpoints at function names. For example, to set a breakpoint at the `main` function, you can use the following command:

```bash
break main
```

```bash
(gdb) break main
(gdb) break helper_function
```

## Running the Program

You can run the program in GDB using the `run` command. For example, to run the program, you can use the following command:

```bash
(gdb) break main
(gdb) break helper_function 
(gdb) run
(gdb) print a
(gdb) print b
(gdb) next

(gdb) print &a
(gdb) x /4xb &a


(gdb) continue


(gdb) print x


(gdb) quit
```

### Notes

Let's break down the GDB command `(gdb) x /4xb &a`:

- `x`: This is the GDB command to examine memory.
- `/4xb`: This specifies how to format the output:
  - `4`: The number of units to display (in this case, 4 units).
  - `x`: The format in which to display the memory (in this case, hexadecimal).
  - `b`: The size of each unit (in this case, bytes).
- `&a`: This is the address of the variable `a`.

So, `(gdb) x /4xb &a` tells GDB to display 4 bytes of memory starting from the address of the variable `a`, formatted as hexadecimal bytes.

### Example

If `a` is an integer variable, it typically occupies 4 bytes of memory. This command will show the contents of these 4 bytes in hexadecimal format.

### Detailed Steps

1. **Print the Address of `a`**:
    ```gdb
    (gdb) print &a
    ```
    This will give you the memory address of the variable `a`.

2. **Examine Memory**:
    ```gdb
    (gdb) x /4xb &a
    ```
    This will display the 4 bytes of memory starting from the address of `a` in hexadecimal format.

### Example Output

Assume the address of `a` is `0x7fffffffeabc` and its value is `5` (which is `0x00000005` in hexadecimal). The output might look like this:

```gdb
0x7fffffffeabc: 0x05 0x00 0x00 0x00
```

This shows the 4 bytes of memory starting from the address `0x7fffffffeabc`, with each byte displayed in hexadecimal format.

### Updated Markdown

```markdown
# Using GDB

To examine memory in GDB, you can use the `x` command. For example, `(gdb) x /4xb &a` does the following:

- `x`: Examine memory.
- `/4xb`: Display 4 units of memory in hexadecimal format, where each unit is 1 byte.
- `&a`: The address of the variable `a`.

This command will display 4 bytes of memory starting from the address of `a` in hexadecimal format. If `a` is an integer, it typically occupies 4 bytes, and this command will show the contents of these bytes.
```