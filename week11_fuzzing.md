# Week 11 - Introduction to Fuzzing: Discovering Vulnerabilities Through Automated Testing


### Introduction

Today we're going to explore one of the most powerful and widely-used techniques in software security testing: fuzzing. By the end of this lecture, you'll understand what fuzzing is, how it works, and how to start implementing basic fuzzing techniques in your own security testing.

Let's begin with a simple analogy: Imagine you're testing a new lock for vulnerabilities. You could try to think of every possible way someone might try to pick it, or you could create a machine that automatically tries thousands of different key shapes until it finds one that works. 

Fuzzing is like that automated key-testing machine, but for software.

### What is Fuzzing? 

Fuzzing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The program is then monitored for crashes, memory leaks, failed assertions, or potential vulnerabilities.

To understand why fuzzing is valuable, let's consider a simple program that asks for a user's age:

```python
def process_age():
    age = input("Enter your age: ")
    age_num = int(age)
    if age_num < 0:
        print("Age cannot be negative")
    elif age_num > 150:
        print("Age seems unrealistic")
    else:
        print(f"Your age is {age_num}")

process_age()
```

A traditional tester might try:
- Normal values (25, 30, 45)
- Edge cases (0, 150)
- Obviously invalid values (-1, 1000)

But what about:
- Non-numeric values ("hello")
- Special characters ("$@#")
- Very long strings ("1" * 1000000)
- Unicode characters ("２５")
- Buffer overflow attempts
- Format string attacks ("%s%s%s%s")

This is where fuzzing shines - it can automatically generate and try thousands of different inputs, including ones that humans might never think to try.

### Types of Fuzzing 

Let's explore the main types of fuzzing:

1. **Mutation-based Fuzzing**
This approach takes valid input samples and mutates them to create test cases. Let's look at a simple example:

Original valid input:
```json
{
    "username": "john_doe",
    "age": 25,
    "email": "john@example.com"
}
```

A mutation-based fuzzer might generate:
```json
{
    "username": "john_doe"""""",
    "age": -99999999,
    "email": "john@example.com%n%n%n"
}
```

2. **Generation-based Fuzzing**

This approach generates test cases from scratch based on input format specifications. For example, if we're testing a PDF parser, we'd create a grammar that defines what a PDF file should look like, then generate variations that are both valid and invalid.

Let's write a simple example of a generation-based fuzzer for testing a function that processes comma-separated values:

```python
import random

def generate_csv_fuzz():
    potential_elements = [
        "123",                    # Normal number
        "-999999999",            # Very negative number
        "9" * 1000,             # Very long number
        "hello",                # Text
        "",                     # Empty string
        ",,,",                  # Multiple delimiters
        "\"unmatched quote",    # Broken quotes
        "§¶®©",                # Special characters
        "\x00\x01\x02"         # Control characters
    ]
    
    num_elements = random.randint(0, 10)
    return ",".join(random.choices(potential_elements, k=num_elements))

# Example usage:
for i in range(5):
    print(f"Test case {i+1}: {generate_csv_fuzz()}")
```

### Fuzzing Strategies and Tools

Modern fuzzing involves several key strategies:

1. **Coverage-guided Fuzzing**
This approach uses program instrumentation to track which parts of the code are executed by each input. Let's look at why this matters:

```python
def process_payment(amount, currency):
    if currency == "USD":
        if amount < 0:
            raise ValueError("Negative amount")
        if amount > 1000000:
            raise ValueError("Amount too large")
        # Process USD payment
    elif currency == "EUR":
        # Process EUR payment
        pass
    elif currency == "GBP":
        # Process GBP payment
        pass
```

A coverage-guided fuzzer would notice that certain inputs (like currency="EUR") reach new code paths and save these inputs for further mutation.

2. **Dictionary-based Fuzzing**

This strategy uses a dictionary of known interesting values. For example, when testing SQL injection vulnerabilities:

```python
sql_fuzzing_dictionary = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT * FROM passwords--",
    "')) OR ((('1'='1",
]
```

### Practical Implementation

Let's implement a simple fuzzer together. We'll create one that tests a function that processes file paths:

```python
import random
import string

def create_path_fuzzer():
    def generate_path_component():
        techniques = [
            lambda: ''.join(random.choices(string.ascii_letters, k=random.randint(1, 10))),
            lambda: '../' * random.randint(1, 5),
            lambda: '/' * random.randint(1, 10),
            lambda: '.' * random.randint(1, 10),
            lambda: '\\' * random.randint(1, 10),
            lambda: '%00',
            lambda: ' ' * random.randint(1, 10),
            lambda: '..' + '/' * random.randint(1, 5),
        ]
        return random.choice(techniques)()

    def generate_path():
        components = [generate_path_component() for _ in range(random.randint(1, 5))]
        return '/'.join(components)

    return generate_path

# Example usage:
fuzzer = create_path_fuzzer()
for i in range(5):
    test_path = fuzzer()
    print(f"Test case {i+1}: {test_path}")
```

### Real-world Applications and Case Studies

Let's examine some real-world vulnerabilities that were discovered through fuzzing:

1. **Heartbleed (CVE-2014-0160)**
   - Discovered through memory fuzzing
   - Showed importance of testing buffer handling
   - Led to widespread adoption of fuzzing in OpenSSL

2. **Apple's Image Parsing Vulnerabilities**
   - Found through file format fuzzing
   - Demonstrated importance of fuzzing file parsers
   - Led to implementation of stronger input validation

### Best Practices and Common Pitfalls

Key considerations when implementing fuzzing:

1. **Seed Selection**
   Choose good initial inputs that exercise different parts of the program.

2. **Monitoring and Logging**
   Implement proper crash monitoring and logging:

```python
import logging
import sys

def setup_fuzzing_logger():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('fuzzing.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('fuzzer')

def monitor_execution(func, input_data):
    logger = setup_fuzzing_logger()
    try:
        result = func(input_data)
        logger.info(f"Success: Input {input_data} produced {result}")
    except Exception as e:
        logger.error(f"Crash detected with input {input_data}: {str(e)}")
        # Save crashing input for later analysis
        with open('crash_inputs.txt', 'a') as f:
            f.write(f"{input_data}\n")
```

3. **Resource Management**
   - Set appropriate timeouts
   - Manage memory effectively
   - Handle clean-up after crashes

### Conclusion and Future Directions 

Fuzzing continues to evolve with new techniques such as:
- Machine learning-guided fuzzing
- Symbolic execution hybrid approaches
- Cloud-based distributed fuzzing

As security professionals, understanding and implementing fuzzing will be crucial in your careers. Start with simple fuzzers like we've discussed today, and gradually move to more sophisticated tools like AFL, libFuzzer, or custom solutions as you gain experience.

