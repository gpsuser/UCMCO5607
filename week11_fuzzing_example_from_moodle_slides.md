# Week 11 - Fuzzing

Fuzzing is a software testing technique that involves providing invalid, unexpected, or random data as inputs to a program. The goal is to identify vulnerabilities, crashes, or unexpected behavior caused by malformed or unexpected inputs.

Fuzzing can be an effective way to discover security vulnerabilities in software, especially when used in combination with other testing techniques. It is commonly used to test the robustness of applications, libraries, and protocols.

Lets start by compiling a simple program that we will use for fuzzing.

## Compiling game.c

The `game.c` code is a simple program that reads a name from the user and prints a message which looks like : `Welcome <name>, - YOU WIN!` or `Welcome <name>, - YOU LOSE... too bad.` 

Here is the code:

```c
// Cybersecurity
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

void prepare_random_num_generator(void);

// Global variables:
char buffer[16];   // to hold the player's name
int  my_number;    // to hold the random number


int main(int argc, char* argv[])
{
	// Program starts here.

  	// Prepare the random number generator
	prepare_random_num_generator();

	// Get a random number (from 0 to RAND_MAX)
	my_number = rand();


	if (argc > 1)
	{
	    strcpy(buffer, argv[1]);   // string copy ( destination, source )

	    printf("Welcome ");        //
	    printf(buffer);            // 
	    printf(", - ");            // 
	
		if (my_number < (int)(RAND_MAX/20))   // Only win one time in 20
		{
			printf("YOU WIN!");
		}	
		else
		{
			printf("YOU LOSE... too bad.");
		}

		printf("\n");              // 'End of line' / 'Newline' character

	}
	else
	{
		printf("######################################\n");
		printf("### Program requires one argument. ###\n");
		printf("### Usage:   progname <yourname>   ###\n");
		printf("######################################\n");
	}


    return 0;
}


// ----------------------------------------------------------------------------

void prepare_random_num_generator(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
	return;
}


// ----------------------------------------------------------------------------
```

To compile the code, use the following command:

```bash
gcc -g game.c -o game -O0
```

The flags `-g` and `-O0` are used to include debugging information and disable optimization, respectively. This makes it easier to analyze the compiled binary and debug any issues.

Test the compiled game binary as follows:

```bash
[cyber@cyberbox week11]$ ./game "grant"
Welcome grant, - YOU WIN!

cyber@cyberbox week11]$ ./game "david"
Welcome david, - YOU LOSE... too bad.

[cyber@cyberbox week11]$ ./game "admin"
Welcome admin, - YOU LOSE... too bad.

[cyber@cyberbox week11]$ ./game "Brent"
Welcome Brent, - YOU LOSE... too bad.

```

Next we consider how a fuzzer can be used to test the game binary.

## Fuzzing the Game Binary

We will use a simple Python fuzzer to test the game binary. The fuzzer will generate random inputs and pass them to the game binary to see how it responds.

Here is a simple Python fuzzer that generates random strings and passes them to the game binary:

```python
import subprocess
import sys

d_base = bytearray(b"AAAAAAAAAAAAAAAA")

#data_in = 'AAAAAAAAAAAA'

#print(bytes(d_base))

for i in range(2**32):

	d_vary = bytearray(i.to_bytes(4, byteorder= 'big'))

	

	for index, value in enumerate(d_vary):
		if value == 0:

			d_vary[index] += 1

	data_in = d_base + d_vary

	print(bytes(data_in))
	out = subprocess.check_output(['./game', bytes(data_in)])

	print(out)


```

To run the fuzzer, save the code to a file (e.g., `sample-fuzzer.py`) and execute it using Python:

```bash
python3 ./sample-fuzzer.py
```

Sample output:

```bash
[cyber@cyberbox week11]$ python3 ./sample-fuzzer.py 
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x01'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x01, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x01'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x01, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x02'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x02, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x03'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x03, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x04'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x04, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x05'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x05, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x06'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x06, - YOU WIN!\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x07'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x07, - YOU LOSE... too bad.\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\x08'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\x08, - YOU LOSE... too bad.\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\t'
b'Welcome AAAAAAAAAAAAAAAA\x01\x01\x01\t, - YOU LOSE... too bad.\n'
b'AAAAAAAAAAAAAAAA\x01\x01\x01\n'
```




