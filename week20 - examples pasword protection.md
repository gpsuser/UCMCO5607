# Week 20 - Examples of password protection

## Passwords

Passwords are the most common form of authentication used to protect access to systems and data. They are used to verify the identity of a user and to grant access to a system or service. Passwords are typically saved and stored in a hashed format to protect them from unauthorized access.

### Password storage

When a user creates a password, it is hashed using a cryptographic algorithm before being stored in a database. Hashing is a one-way process that converts the password into a fixed-length string of characters that cannot be reversed to reveal the original password. This ensures that even if the database is compromised, the passwords remain secure.

### Password Encryption vs. Password Hashing

Password encryption is a reversible process that converts the password into an encrypted form that can be decrypted to reveal the original password. This method is not recommended for storing passwords as it poses a security risk if the encryption key is compromised.

Password hashing, on the other hand, is a one-way process that converts the password into a fixed-length string of characters that cannot easily be reversed. This method is more secure as it protects the passwords from being easily decrypted.

For password protection, hashing is commonly used because, even if someone gets access to the hashed passwords, they can't easily reverse-engineer them to find the original passwords. To further enhance security, techniques like "salting" are often employed, where a unique value (a "salt") is added to each password before hashing to prevent attackers from using precomputed tables (rainbow tables) to crack the hashes. 

`Verification`: When a user attempts to log in, the system hashes the entered password and compares it to the stored hash. If they match, the user is granted access.

`Best Practices`: Using strong cryptographic hash functions (such as bcrypt, Argon2, SHA-256) and adding a "salt" (a unique random value) to each password before hashing helps protect against common attacks like rainbow table attacks.

Encryption could be used in the password storage process, but it requires storing the encryption keys securely, which introduces additional complexity and potential points of failure.

### Crytographic Hash Functions

Both hash functions and cryptographic hash functions are used to transform input data into a fixed-size string of characters. However, there are key differences between them:

#### Purpose:

`Hash Function`: Used for various purposes such as indexing data in hash tables, data deduplication, and checksums for data integrity.

`Cryptographic Hash Function`: Specifically designed for security purposes, such as password hashing, digital signatures, and data integrity verification in cryptographic applications.

#### Security:

`Hash Function`: Does not necessarily need to be secure; it just needs to produce a unique output for each unique input. However, it might be prone to collisions (two different inputs producing the same output).

`Cryptographic Hash Function`: Must be secure and fulfill three critical properties: pre-image resistance, second pre-image resistance, and collision resistance. These properties ensure it is computationally infeasible to reverse the hash, find two different inputs with the same hash, or find an input with a specific hash.

#### Examples:

`Hash Function`: Simple hash functions like the ones used in hash tables (e.g., modulo operation).

`Cryptographic Hash Function`: Secure hashing algorithms such as SHA-256, SHA-3, and bcrypt.

---

Note that - **a cryptographic hash of a password is not considered to be encrypted**. Here’s why:

Hashing is a one-way function that converts data (like a password) into a fixed-size string of characters (the hash). This process is irreversible, meaning you cannot convert the hash back into the original password.

Encryption is a reversible process that converts plaintext data into a different format using a key. The original data can be retrieved using a corresponding decryption key.

So, while both techniques aim to protect data, hashing provides a way to verify passwords without storing the original passwords, whereas encryption allows for the data to be recovered in its original form by someone who has the decryption key.

---

### Constructing a simple cryptographic hash function - from an existing hash function

Here's an example of how you can construct a simple cryptographic hash function using the SHA-256 hash function available in Python's `hashlib` library. 

You will see how to add a salt to the password before hashing to enhance security.

```python
import hashlib
import os

def hash_password(password: str, salt: bytes = None) -> str:
    # Generate a random salt if one is not provided
    if salt is None:
        salt = os.urandom(16)
    
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Concatenate salt and password bytes
    salted_password = salt + password_bytes
    
    # Hash the salted password using SHA-256
    hash_object = hashlib.sha256(salted_password)
    password_hash = hash_object.hexdigest()
    
    # Return the salt and hash in a hexadecimal format
    return salt.hex() + password_hash

# Example usage
password = "your_secure_password"
hashed_password = hash_password(password)
print(f"Hashed password: {hashed_password}")
```

Here's a step-by-step breakdown of the code:

1. **Import required libraries**: We use the `hashlib` library for hashing and the `os` library to generate random bytes for the salt.
2. **Generate a random salt**: If a salt is not provided, the function generates a random 16-byte salt using `os.urandom()`.
3. **Convert password to bytes**: The password is converted to bytes using UTF-8 encoding.
4. **Concatenate salt and password bytes**: The salt and password bytes are concatenated.
5. **Hash the salted password**: The `hashlib.sha256()` function is used to hash the concatenated salt and password bytes.
6. **Return the salt and hash**: The salt and password hash are returned in hexadecimal format.

### Verifying a passord using a hash function with salt

To verify a password, you'll need to use the same salt and hash function that were used when the password was initially hashed. Here’s how you can do it in Python:

```python
import hashlib
import os

def hash_password(password: str, salt: bytes = None) -> str:
    # Generate a random salt if one is not provided
    if salt is None:
        salt = os.urandom(16)
    
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Concatenate salt and password bytes
    salted_password = salt + password_bytes
    
    # Hash the salted password using SHA-256
    hash_object = hashlib.sha256(salted_password)
    password_hash = hash_object.hexdigest()
    
    # Return the salt and hash in a hexadecimal format
    return salt.hex() + password_hash

def verify_password(stored_hash: str, provided_password: str) -> bool:
    # Extract the salt from the stored hash (first 32 characters for a 16-byte salt)
    salt_hex = stored_hash[:32]
    salt = bytes.fromhex(salt_hex)
    
    # Extract the actual hashed password from the stored hash
    stored_password_hash = stored_hash[32:]
    
    # Hash the provided password with the extracted salt
    provided_hash = hash_password(provided_password, salt)[32:]
    
    # Compare the stored hash with the provided hash
    return provided_hash == stored_password_hash

# Example usage
password = "your_secure_password"
hashed_password = hash_password(password)
print(f"Stored hashed password: {hashed_password}")

# Verify the password
is_verified = verify_password(hashed_password, "your_secure_password")
print(f"Password verified: {is_verified}")
```

Here's a step-by-step breakdown of the verification process:

1. **Extract the Salt**: The stored hash is split into the salt (first 32 characters for a 16-byte salt in hexadecimal) and the actual hashed password.
2. **Hash the Provided Password**: The provided password is hashed using the extracted salt.
3. **Compare Hashes**: The hash of the provided password is compared to the stored hash. If they match, the password is verified.

This ensures that only the correct password will match the stored hash, making the verification process secure.

Next, afinal note on password spraying.

## Password Spraying

Password spraying is a type of brute force attack where an attacker attempts to gain unauthorized access to multiple accounts by trying a few commonly used passwords across many different usernames. This method helps the attacker avoid account lockouts that would typically occur when trying many passwords on a single account.

**How a Password Spraying Attack Works**:

1. **Acquire Usernames**: The attacker gathers a list of usernames, often through data breaches or public sources.
2. **Attempt Logins**: The attacker tries a common password (e.g., "Password123") across all the usernames.
3. **Repeat**: The attacker repeats the process with different common passwords until they successfully breach an account.

**Why It's Effective**:

- **Avoids Lockouts**: By spreading the attempts across many accounts, the attacker avoids triggering account lockout mechanisms that would occur with traditional brute force attacks.
- **Exploits Weak Passwords**: Many users still use weak or common passwords, making this attack method effective.

**Mitigation Strategies**:

- **Implement Multi-Factor Authentication (MFA)**: Adding an extra layer of security makes it harder for attackers to gain access even if they have the correct password.
- **Enforce Strong Password Policies**: Require users to create complex passwords that are harder to guess.
- **Monitor Login Activity**: Keep an eye on unusual login patterns, such as multiple failed attempts from different accounts.

For more detailed information, you can check out resources like the [OWASP Foundation](https://owasp.org/www-community/attacks/Password_Spraying_Attack) and [CrowdStrike](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/password-spraying/).

