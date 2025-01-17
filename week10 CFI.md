# Week 10 - Control Flow Integrity (CFI) 

CFI is a powerful security mechanism used to prevent attackers from hijacking the intended execution flow of a program. 

It does this by enforcing valid control flow paths, making it significantly harder for attackers to exploit vulnerabilities and execute malicious code.

CFI is implemented through a multi-stage process, which includes:

## 1. Static Analysis Phase:

`Purpose`: This phase analyzes the program's source code or binary without actually executing it. The goal is to identify all legitimate control flow paths.
`Process`:
* `Disassembly/Decompilation`: If starting from a binary, the code is disassembled to understand its instructions. If source code is available, it might be decompiled into an intermediate representation.

* `Control Flow Graph (CFG) Construction`: A CFG is created to represent the program's control flow. Nodes in the CFG represent basic blocks of code (sequences of instructions with a single entry and exit point), and edges represent possible jumps or branches between these blocks.

* `Indirect Call/Jump Target Identification`: The analysis focuses on identifying indirect calls and jumps (e.g., function pointer calls, virtual function calls, or jumps through register values). These are the primary targets for attackers as they can be manipulated to redirect execution.

Example (Simplified):

```c
void (*func_ptr)(); // Function pointer

int main() {
  // ... some code ...
  func_ptr = &function_A; // Assign address of function_A
  // ... some code ...
  func_ptr(); // Indirect call through function pointer
  // ... some code ...
  return 0;
}

void function_A() {
  // ... some code ...
}

void function_B() {
  // ... some code ...
}

```

In this example, static analysis would:

* Identify `func_ptr()` as an indirect call.
* Determine that `func_ptr` can legitimately point to `function_A`.
* (Ideally) Infer that `function_B` should not be a valid target for `func_ptr`.

## 2. Dependency Analysis Phase

* **Purpose:** Refine the CFI policy by understanding relationships and dependencies in the code.
* **Process:**
    * `Data flow analysis` to track how data influences indirect call/jump targets.
    * `Context sensitivity` to create more precise CFI rules.
    * `Type analysis` to restrict valid targets based on function signatures.
* **Example (Continuing from above):**

Dependency analysis might:

* Analyze the data flow to confirm that no other code modifies `func_ptr` after it's assigned to `function_A`.
* If the code had type information, it could enforce that `func_ptr` can only point to functions with a specific signature.

## 3. Runtime Verification Phase

* **Purpose:** Enforce the CFI policy during program execution.
* **Process:**
    * `Instrumentation`: The program is modified (instrumented) to include runtime checks before each indirect call/jump.

    * ` CFI Table Lookup`: At runtime, before an indirect call/jump, the target address is checked against a CFI table (created based on the previous phases) to see if it's a valid destination.

    * `Enforcement`: If the target is not allowed, the program terminates or takes a recovery action to prevent exploitation.
* **Example (Continuing from above):**

At runtime:

* Before the `func_ptr()` call, the CFI check would ensure that the address stored in `func_ptr` matches the address of `function_A`.
* If an attacker attempts to overwrite `func_ptr` with the address of `function_B` or any other invalid location, the CFI check would fail, and the program would be halted.

Simple Code Example (Illustrative):

```c
// Simplified CFI check (actual implementations are more complex)
void enforce_cfi(void *target_addr) {
  // Look up valid targets in the CFI table (not shown here)
  if (is_valid_target(target_addr)) {
    // Call the target function
    ((void (*)())target_addr)(); 
  } else {
    // CFI violation!
    abort(); // Terminate the program
  }
}

int main() {
  // ...
  enforce_cfi(func_ptr); // CFI check before the indirect call
  // ...
}
```

---

Next, let's create a simplified "Hello World" example with a basic CFI implementation. We'll focus on the core concepts and use some illustrative assembly to show how it works under the hood.

## "Hello World" CFI Example

**1. The Code:**

```C
#include <stdio.h>

void greet() {
  printf("Hello, World!\n");
}

int main() {
  void (*func_ptr)(); // Function pointer
  func_ptr = &greet;  // Assign greet's address
  func_ptr();        // Indirect call
  return 0;
}
```

**2. Static Analysis (Manual):**

`Identify Indirect Calls`: In this simple case, we have one indirect call: `func_ptr()`.

`Determine Valid Targets`: `func_ptr` is assigned the address of the `greet` function. So, `greet` is the only valid target.

**3. CFI Table Construction (Simplified):**

We'll create a very basic CFI table. In a real implementation, this would be more sophisticated and likely integrated into the compiler or linker.

```c
// Our CFI table (an array of function pointers)
void (*cfi_table[])() = {&greet}; 

// A function to check if a target is valid
int is_valid_target(void *target) {
  // In this simple case, we just check if the target 
  // matches the only entry in our table.
  return (target == cfi_table[0]); 
}
```

**4. Runtime Verification:**

We'll add a CFI check before the indirect call:

```c
int main() {
  // ... (same as before) ...

  if (is_valid_target(func_ptr)) {
    func_ptr(); 
  } else {
    printf("CFI Violation!\n");
    abort();
  }

  return 0;
}
```

**5. Assembly (Illustrative):**

Let's imagine how the compiler might translate the indirect call and CFI check into assembly (this is a simplified representation):

```assembly
// Indirect call without CFI:
mov rax, [func_ptr]  ; Load the address from func_ptr into rax
call rax             ; Call the function at the address in rax

// Indirect call with CFI:
mov rax, [func_ptr]      ; Load address
cmp rax, [cfi_table]   ; Compare with allowed target
jne cfi_violation       ; Jump if not equal

call rax                 ; Call the function

cfi_violation:
  ; Handle the violation (e.g., print error, abort)
```

Explanation:

* The `mov` instruction loads the address stored in `func_ptr` into the `rax` register (which typically holds the function address for calls).
* The `cmp` instruction compares the address in `rax` with the address stored in our `cfi_table`.
The `jne` (jump if not equal) instruction jumps to the `cfi_violation` label if the addresses don't match.


Key Takeaways:

* This is a highly simplified example to demonstrate the basic principles.
* Real-world CFI is much more complex, involving compiler integration, binary instrumentation, and more sophisticated table structures.
* CFI helps prevent attackers from exploiting vulnerabilities that allow them to overwrite function pointers or return addresses to redirect execution.   
* This example hopefully gives you a clearer understanding of how CFI works at a fundamental level

## CFI and ROP Exploits

CFI is effective against ROP (Return-Oriented Programming) attacks because:

* **ROP relies on chaining gadgets:**  Short code sequences ending with `ret`.
* **CFI restricts valid targets:** Gadgets are often in unexpected locations not in the CFI table.
* **CFI disrupts the chain:** When a gadget's address is not in the CFI table, execution is blocked.

**Important:** CFI is not perfect and should be used with other security measures.

This Markdown content provides a comprehensive overview of CFI, its implementation phases, a simple example, and its role in mitigating ROP exploits. You can copy and paste this into a `.md` file and add your code snippets where indicated.

---

Question: 
If code was injected during an ROP exploit - any function called in the malicious code would not be found in CFI table - and so the malicious code would not be able to execute that function --- is this correct?

---

Typcally yes: If an attacker injects code during an ROP exploit and tries to call a function that is not a valid target in the CFI table, the CFI runtime check would fail. This would prevent the attacker from executing the injected malicious code and disrupt the exploit chain. By enforcing valid control flow paths, CFI helps protect against such attacks by ensuring that only legitimate code paths are followed.

---

Stated slightly differently - that's a key way CFI helps mitigate ROP (Return-Oriented Programming) attacks.

Here's a breakdown of how CFI disrupts ROP:

ROP Exploits:

The Goal: ROP exploits aim to chain together short code sequences ("gadgets") that already exist within the program or its libraries. These gadgets end with a ret instruction (return instruction), allowing an attacker to manipulate the stack and control the flow of execution.

Bypassing Traditional Defenses: ROP is particularly dangerous because it bypasses defenses like Data Execution Prevention (DEP/NX), which prevents code execution from non-executable memory regions like the stack. ROP uses existing code, so it doesn't need to inject new executable code.

CFI's Role:

* `Restricting Valid Targets`: CFI enforces valid control flow paths. The CFI table, built during the static analysis and dependency analysis phases, defines the legitimate targets for indirect calls and jumps.

* `Disrupting the Chain`: When an attacker tries to execute a ROP chain, they essentially hijack the control flow by overwriting return addresses or function pointers to point to these gadgets. 

    * However, since the gadgets are often located in unexpected places (e.g., the middle of a function), the addresses of these gadgets won't be present in the CFI table.

* `Blocking Execution`: When the program tries to execute a gadget as part of the ROP chain, the CFI runtime check will fail.

The target address won't match any valid entry in the CFI table, and the program will terminate or take a recovery action, preventing the exploit from continuing.

In essence, CFI puts guardrails on the program's execution flow, making it very difficult for attackers to chain together gadgets and achieve arbitrary code execution.

#### Important Note:

While CFI is a powerful defense, it's not foolproof. Sophisticated attackers may try to:

* Find Gadgets within Allowed Targets: Attackers might try to find gadgets within functions that are already listed as valid targets in the CFI table.

* Circumvent CFI Checks: There might be vulnerabilities in the CFI implementation itself that attackers can exploit to bypass the checks.

* Therefore, CFI is most effective when used in combination with other security mechanisms to provide a layered defense.

