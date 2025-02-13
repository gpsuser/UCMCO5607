# Week 14: Introduction to Penetration Testing

Penetration testing is a critical aspect of cybersecurity that involves simulating real-world attacks to identify vulnerabilities in systems. This lecture will cover the fundamental concepts of penetration testing, including hacker classifications, the penetration testing lifecycle, and the use of Scapy for network analysis.

## Learning Objectives

By the end of this lecture, students will be able to:

1. Differentiate between various types of hackers and their motivations
2. Understand the fundamental concepts of penetration testing
3. Explain each phase of the penetration testing lifecycle
4. Demonstrate basic usage of information gathering tools
5. Apply Scapy for network packet manipulation in penetration testing scenarios

## 1. Types of Hackers

### Understanding Hacker Classifications

In the realm of cybersecurity, hackers are typically classified based on their intentions and ethical standards. Here's a comprehensive breakdown:

| Type | Description | Motivation | Legal Status |
|------|-------------|------------|--------------|
| White Hat | Ethical hackers who work to protect systems | Security improvement | Legal |
| Black Hat | Malicious hackers who exploit systems illegally | Personal gain, damage | Illegal |
| Grey Hat | Operate in both ethical and unethical spaces | Mixed motivations | Questionable |
| Script Kiddies | Inexperienced hackers using pre-made tools | Recognition, curiosity | Usually illegal |
| Hacktivists | Hack for social or political causes | Ideology, activism | Usually illegal |
| State-Sponsored | Government-backed cyber operations | National interests | Varies |

## 2. Penetration Testing

Penetration testing is a systematic process of evaluating the security of computer systems, networks, or web applications by simulating real-world attacks in a controlled environment.

### Key Characteristics:

- **Authorization**: Conducted with explicit permission
- **Scope**: Clearly defined boundaries and targets
- **Documentation**: Comprehensive reporting of findings
- **Methodology**: Structured approach following industry standards
- **Risk Management**: Careful consideration of system stability

## 3. Penetration Testing Lifecycle

### 3.1 Engagement Phase

The engagement phase establishes the groundwork for the entire penetration testing process:

- **Scope Definition**: Clearly outlining testing boundaries
- **Rules of Engagement**: Establishing testing parameters
- **Legal Considerations**: Obtaining necessary permissions
- **Timeline Planning**: Setting project milestones

### 3.2 Information Gathering

This phase involves collecting all available information about the target:

```bash
# Basic information gathering commands
whois domain.com
dig domain.com
nslookup domain.com
```

### 3.3 Information Gathering Tools

Popular tools for reconnaissance:

1. **OSINT Framework**
2. **Maltego**
3. **Recon-ng**
4. **TheHarvester**
5. **Netcat**

Example Netcat usage:

Make sure netcat is installed on your system:


```bash
nc 

```bash
https://nmap.org/download.html#windows
```



```bash

Example using TheHarvester:

```bash
theHarvester -d target.com -b all
```

### 3.4 Information Gathering Techniques

#### Passive Reconnaissance
- Website analysis
- Public records
- Social media investigation
- DNS information

#### Active Reconnaissance
- Network scanning
- Service enumeration
- OS fingerprinting

### 3.5 Footprinting

Footprinting involves creating a comprehensive map of the target environment:

```python
# Simple Python script for basic footprinting
import socket
import sys

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Unable to resolve domain"

def main():
    domain = input("Enter domain name: ")
    ip = get_ip_address(domain)
    print(f"IP Address for {domain}: {ip}")

if __name__ == "__main__":
    main()
```

### 3.6 Scanning

Network scanning techniques and tools:

- Port scanning
- Vulnerability scanning
- Service enumeration

Example using Nmap:

```bash
# Basic Nmap scan
nmap -sV -sC target.com

# Aggressive scan
nmap -A target.com
```

### 3.7 Threat Modeling

Using the STRIDE methodology:

| Threat | Description | Example |
|--------|-------------|---------|
| Spoofing | Impersonating something or someone | DNS spoofing |
| Tampering | Modifying data or code | Man-in-the-middle attacks |
| Repudiation | Denying actions | Log tampering |
| Information Disclosure | Exposing information | Data breaches |
| Denial of Service | Making something unavailable | DDoS attacks |
| Elevation of Privilege | Gaining higher privileges | Buffer overflow exploits |

### 3.8 Vulnerability Assessment

Systematic approach to finding vulnerabilities:

1. Asset identification
2. Vulnerability scanning
3. Risk assessment
4. Prioritization

### 3.9 Exploitation

**Note**: This section focuses on authorized testing only.

Basic exploitation framework usage:

```python
# Example of a safe port scanner
import socket

def port_scan(target, ports):
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
        s.close()
```

## 4. Introduction to Scapy

Scapy is a powerful Python library for packet manipulation. Here's a basic introduction:

```python
from scapy.all import *

# Simple ping
def ping(host):
    # Create ICMP packet
    ping_packet = IP(dst=host)/ICMP()
    # Send packet and wait for response
    reply = sr1(ping_packet, timeout=2)
    if reply:
        print(f"{host} is responding")
    else:
        print(f"{host} is not responding")
```

## 5. Case Study: Using Scapy for Network Analysis

### Scenario: Network Traffic Analysis

```python
from scapy.all import *

def analyze_traffic(interface="eth0"):
    """
    Capture and analyze network traffic
    """
    def packet_callback(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"IP Packet: {src_ip} -> {dst_ip}")
            
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"TCP Ports: {sport} -> {dport}")
    
    # Start sniffing
    sniff(iface=interface, prn=packet_callback, count=10)

# Usage
# analyze_traffic("your_interface")
```

## Conclusion

This lecture has covered the fundamental aspects of penetration testing, from understanding different types of hackers to practical implementation using tools like Scapy. Remember that ethical hacking requires:

- Proper authorization
- Clear documentation
- Ethical considerations
- Legal compliance
- Continuous learning

## References

1. Engebretson, P. (2013). The Basics of Hacking and Penetration Testing. Syngress.
2. Allen, L. (2012). Advanced Penetration Testing for Highly-Secured Environments. Packt Publishing.
3. NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment
4. OWASP Testing Guide v4.0
5. Scapy Documentation: https://scapy.readthedocs.io/

## Additional Resources

- OWASP Top 10
- Penetration Testing Execution Standard (PTES)
- Certified Ethical Hacker (CEH) Materials
- Offensive Security Documentation

---

