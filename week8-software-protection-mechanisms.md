# Week 8 - Software Protection Mechanisms

## Understanding Stack Canaries and Buffer Overflow Detection

This lecture content explains how stack canaries work as a security mechanism for detecting buffer overflows, with a practical C code example.

## Introduction

Stack canaries are values placed on the stack between buffer variables and control data (like return addresses) to detect buffer overflows. When a buffer overflow occurs, it typically overwrites memory sequentially, meaning it will corrupt the canary value before reaching critical stack data.

## Example Implementation

Here's a complete example demonstrating stack canary implementation:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

void __attribute__((constructor)) setup_canary(void);
void check_canary(void);

// Global canary value
static unsigned long canary;

// Setup function to initialize our canary
void setup_canary(void) {
    // In real implementations, this would use CPU-provided random values
    // For demonstration, we'll use a fixed value
    canary = 0xDEADBEEF;
}

void vulnerable_function(const char* input) {
    unsigned long local_canary = canary;  // Store canary on stack
    char buffer[8];                       // Small buffer for demonstration
    
    printf("Stack layout before copy:\n");
    printf("buffer address:     %p\n", (void*)buffer);
    printf("local_canary addr:  %p\n", (void*)&local_canary);
    printf("saved EBP addr:     %p\n", (void*)(__builtin_frame_address(0)));
    
    // Intentionally vulnerable strcpy
    strcpy(buffer, input);
    
    // Check if canary was modified
    if (local_canary != canary) {
        printf("\n!!! Stack overflow detected! Canary corrupted !!!\n");
        printf("Expected: 0x%lx\n", canary);
        printf("Found:    0x%lx\n", local_canary);
        exit(1);
    }
    
    printf("\nFunction completed successfully\n");
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    
    printf("Global canary value: 0x%lx\n\n", canary);
    vulnerable_function(argv[1]);
    
    return 0;
}
```

## Stack Layout Analysis

### Normal State
When `vulnerable_function` is called, the stack frame is arranged as follows (from high to low addresses):

```
Higher addresses
+------------------+
| Return Address   |  <- Where execution will resume after function returns
+------------------+
| Saved EBP       |  <- Previous frame pointer
+------------------+
| Local Canary    |  <- Our guard value (0xDEADBEEF)
+------------------+
| Buffer[8]       |  <- User input goes here
+------------------+
Lower addresses
```

### Canary Protection Mechanism

1. **Implementation Details**
   - A global canary value (0xDEADBEEF in our example) is initialized at program start
   - The canary value is copied to the stack frame between the buffer and saved frame pointer
   - Real implementations use random values instead of fixed ones

2. **Normal Operation**
   - The buffer is allocated with 8 bytes of space
   - The local canary sits between the buffer and the saved base pointer
   - Any buffer overflow must corrupt the canary before reaching critical stack data

3. **During Buffer Overflow**
   - First 8 bytes fill the buffer
   - Additional bytes overflow into the canary value
   - Further bytes would reach the saved base pointer and return address
   - Program detects overflow by comparing local and global canary values

## Testing the Implementation

To test the code:

```bash
# Compile
gcc -fno-stack-protector -o canary_test canary_example.c

# Normal operation
./canary_test "test"

# Trigger overflow
./canary_test "AAAAAAAABBBBBBBB"
```

## Real-World Implementations

Production implementations like GCC's stack protector include additional features:

- True random canary generation
- Null bytes in canary values to stop string functions
- Compiler-level integration
- Automatic protection for at-risk functions
- Sophisticated failure handling mechanisms

## Key Security Considerations

1. The canary serves as a "tripwire" - any buffer overflow must corrupt it before reaching critical data
2. Placing the canary between buffers and frame pointers protects against return address attacks
3. Random canary values in real implementations prevent attackers from forging valid canaries
4. The implementation must be careful not to leak canary values
5. Stack canaries are just one of many security measures and should be combined with other protections

## Further Reading

- GCC Stack Protector documentation
- "Stack Smashing Protector" academic papers
- Operating system security guides on stack protection mechanisms
- Buffer overflow prevention techniques and best practices



## Types of Canaries

### 1. Terminator Canaries

Terminator canaries use special characters that terminate string operations, making it harder for attackers to exploit string operations.

```c
#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) setup_terminator_canary(void);
static unsigned long terminator_canary;

void setup_terminator_canary(void) {
    // Canary contains: NULL, CR, LF, and -1
    terminator_canary = ((unsigned long)0x00 << 24) | 
                       ((unsigned long)0x0A << 16) | 
                       ((unsigned long)0x0D << 8)  | 
                       ((unsigned long)0xFF);
}

void check_terminator_canary(unsigned long local_canary) {
    if (local_canary != terminator_canary) {
        printf("Terminator canary corrupted!\n");
        exit(1);
    }
}
```

### 2. Random Canaries

Random canaries use cryptographically secure random values, typically generated at program start.

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

void __attribute__((constructor)) setup_random_canary(void);
static unsigned long random_canary;

void setup_random_canary(void) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, &random_canary, sizeof(random_canary));
        close(fd);
    }
}

void check_random_canary(unsigned long local_canary) {
    if (local_canary != random_canary) {
        printf("Random canary corrupted!\n");
        exit(1);
    }
}
```

### 3. Random XOR Canaries

Random XOR canaries combine random values with control data to create a stronger protection mechanism.

```c
#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) setup_xor_canary(void);
static unsigned long xor_canary;

void setup_xor_canary(void) {
    // Get random value
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, &xor_canary, sizeof(xor_canary));
        close(fd);
    }
}

void vulnerable_function_xor(const char* input) {
    // Get frame pointer for XOR operation
    void* frame_ptr = __builtin_frame_address(0);
    unsigned long local_canary = xor_canary ^ (unsigned long)frame_ptr;
    
    char buffer[8];
    strcpy(buffer, input);
    
    // Check XORed canary
    if (local_canary != (xor_canary ^ (unsigned long)frame_ptr)) {
        printf("XOR canary corrupted!\n");
        exit(1);
    }
}
```

## Additional Security Measures for Buffer Overflow Prevention

### A. Bounds Checking Implementation

Here's an example of implementing bounds checking in C:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* data;
    size_t size;
    size_t capacity;
} SafeBuffer;

SafeBuffer* create_safe_buffer(size_t capacity) {
    SafeBuffer* buf = malloc(sizeof(SafeBuffer));
    buf->data = malloc(capacity);
    buf->size = 0;
    buf->capacity = capacity;
    return buf;
}

int safe_write(SafeBuffer* buf, const char* data, size_t length) {
    if (buf->size + length > buf->capacity) {
        printf("Buffer overflow prevented!\n");
        return -1;
    }
    
    memcpy(buf->data + buf->size, data, length);
    buf->size += length;
    return 0;
}

void destroy_safe_buffer(SafeBuffer* buf) {
    free(buf->data);
    free(buf);
}
```

### B. Address Space Layout Randomization (ASLR)

#### Position Independent Executable (PIE) Example

```c
// Compile with: gcc -fPIE -pie -o pie_example pie_example.c
#include <stdio.h>

int main() {
    int local_var = 42;
    printf("Main function address: %p\n", (void*)main);
    printf("Local variable address: %p\n", (void*)&local_var);
    return 0;
}
```

#### Position Independent Code (PIC) Example

```c
// shared_lib.c - Compile with: gcc -fPIC -shared -o libshared.so shared_lib.c
#include <stdio.h>

void __attribute__((constructor)) init_lib(void) {
    printf("Library loaded at: %p\n", (void*)init_lib);
}

// Global Offset Table (GOT) and Procedure Linkage Table (PLT) demonstration
extern void external_function(void);
void (*function_ptr)(void) = external_function;
```

### C. Sandboxing Example

```c
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <linux/seccomp.h>

int setup_sandbox(void) {
    scmp_filter_ctx ctx;
    
    // Initialize seccomp context
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        return -1;
    }
    
    // Allow only specific system calls
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    
    // Load the rules
    return seccomp_load(ctx);
}
```

### D. Control Flow Integrity (CFI) Example

```c
// Compile with: clang -fsanitize=cfi -flto -fvisibility=hidden
#include <stdio.h>

// Function pointer type for virtual calls
typedef void (*vfunc)(void);

// Base class with virtual function
class Base {
public:
    virtual void virtual_func() {
        printf("Base virtual_func\n");
    }
    virtual ~Base() {}
};

// Derived class
class Derived : public Base {
public:
    virtual void virtual_func() override {
        printf("Derived virtual_func\n");
    }
};

int main() {
    Base* obj = new Derived();
    vfunc fp = (vfunc)obj->virtual_func;  // CFI checks this cast
    fp();  // CFI checks this call
    delete obj;
    return 0;
}
```

## Implementation Notes

### NX/DEP (No Execute/Data Execution Prevention)
- Modern compilers support NX by default
- Stack and heap memory regions are marked as non-executable
- Compile with: `gcc -z noexecstack`

### W^X (Write XOR Execute)
- Memory pages cannot be both writable and executable
- Implemented at OS level
- Enforced through memory protection flags

### BSS (Block Started by Symbol)
- Uninitialized data section
- Zero-initialized at program start
- Separate from stack and heap

For comprehensive protection, these measures should be used in combination:
1. Enable stack canaries (`-fstack-protector-strong`)
2. Enable ASLR (system-wide and PIE/PIC)
3. Implement bounds checking
4. Use NX/DEP protection
5. Enable CFI where available
6. Apply appropriate sandboxing
7. Follow secure coding practices

## Security Best Practices

1. **Input Validation**
   - Validate all input lengths and contents
   - Use safe string functions (strncpy, strncat)
   - Implement proper bounds checking

2. **Memory Management**
   - Use safe alternatives to unsafe functions
   - Implement proper buffer size checks
   - Consider using smart pointers in C++

3. **Compiler Options**
   - Enable all security flags
   - Use stack protection mechanisms
   - Enable runtime checks where appropriate

4. **System Configuration**
   - Enable ASLR system-wide
   - Configure proper memory permissions
   - Implement proper sandboxing policies




## Technical Glossary and Concepts

### Canary Types and Components

#### Terminator Canaries
- **Null Terminator (0x00)**: String termination character in C; stops string manipulation functions
- **Carriage Return (0x0D)**: ASCII control character that terminates many string inputs
- **Line Feed (0x0A)**: Another string termination character used in text processing
- **EOF (-1/0xFF)**: End-of-file marker that terminates input operations

Role in Detection: These characters are chosen because they typically terminate string operations. If an overflow uses string operations (like strcpy), these terminators will stop the copy operation, making it harder to overwrite the full canary value.

#### Random Canaries
- **/dev/urandom**: Unix special file providing cryptographic-grade random numbers
- **PRNG (Pseudo-Random Number Generator)**: Algorithm for generating sequences of numbers with random properties
- **Entropy Pool**: System's collection of random environmental data used to generate random numbers

Role in Detection: Random canaries make it impossible for attackers to predict the canary value, preventing them from crafting payloads that preserve the canary while overwriting other data.

#### Random XOR Canaries
- **XOR Operation**: Bitwise exclusive-OR operation used to combine values
- **Control Data**: Critical program data like return addresses and frame pointers
- **Frame Pointer**: Register (EBP/RBP) pointing to the current stack frame

Role in Detection: By XORing the canary with control data, any modification to either the canary or the control data will be detected, providing double protection.

### Memory Protection Mechanisms

#### Address Space Layout Randomization (ASLR)
- **Virtual Address Space**: Process's view of memory, isolated from physical memory
- **Base Address**: Starting point of a program section in memory
- **Memory Segments**: Different sections of program memory (text, data, stack, heap)

Components:
- **BSS (Block Started by Symbol)**:
  - Memory section containing uninitialized global variables
  - Zero-initialized at program start
  - Target for overflow attacks due to predictable content

- **PIE (Position Independent Executable)**:
  - Executable that can run at any memory location
  - All code addresses are relative to current position
  - Complicates exploitation by randomizing code location

- **PIC (Position Independent Code)**:
  - Code that can execute regardless of its absolute address
  - Uses relative addressing for all operations
  - Essential for shared libraries and ASLR

Role in Detection: ASLR makes it harder for attackers to predict where vulnerable buffers or useful code fragments are located, complicating exploitation even if an overflow occurs.

#### Memory Protection Flags

- **NX (No Execute)/DEP (Data Execution Prevention)**:
  - Memory permission flag preventing code execution in data areas
  - Marks stack and heap as non-executable
  - Prevents direct execution of injected code

- **W^X (Write XOR Execute)**:
  - Policy ensuring memory is never both writable and executable
  - Enforced through page permissions
  - Prevents code modification and execution

Role in Detection: These flags prevent direct execution of injected code, forcing attackers to use more complex techniques that are easier to detect.

### Runtime Protection Mechanisms

#### Bounds Checking
- **Buffer Bounds**: Valid memory range for a buffer
- **Size Tracking**: Runtime monitoring of buffer usage
- **Length Validation**: Checking input size before operations

Role in Detection: Actively prevents overflows by validating all memory operations before they occur.

#### Sandboxing
- **Seccomp**: Linux security facility for syscall filtering
- **Syscall**: System call interface between user programs and kernel
- **Process Isolation**: Containment of process activities and resources

Role in Detection: Limits the impact of successful exploits by restricting process capabilities.

#### Control Flow Integrity (CFI)
- **Control Flow Graph**: Map of valid program execution paths
- **Indirect Calls**: Function calls through pointers
- **Virtual Functions**: Polymorphic functions in C++
- **VTABLE**: Virtual function table used for dynamic dispatch

Role in Detection: Ensures program execution follows valid paths only, detecting attempts to redirect control flow through overflow attacks.

### Implementation Components

#### Compiler Protections
- **Stack Guard**: GCC's implementation of stack canaries
- **-fstack-protector**: Compiler flag enabling stack protection
- **Link-Time Optimization (LTO)**: Enables whole-program analysis for security

Role in Detection: Provides built-in mechanisms for detecting and preventing various types of buffer overflows.

#### Runtime Checks
- **Function Prologue**: Code setting up stack frame and protections
- **Function Epilogue**: Code validating protections before return
- **Shadow Stack**: Secondary stack tracking return addresses

Role in Detection: Performs continuous validation during program execution to detect overflow attempts.

This glossary covers the technical terms used in modern buffer overflow protection systems. Each mechanism plays a specific role in either preventing overflows or detecting them when they occur. The most effective protection comes from combining multiple mechanisms, as each addresses different aspects of the overflow problem.

