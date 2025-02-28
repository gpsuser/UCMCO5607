# NMAP and Active Network Scanning

## Introduction

Network mapping and security assessment are foundational skills in modern cybersecurity. As networks grow increasingly complex, security professionals need robust tools to gain visibility into network environments, identify potential vulnerabilities, and secure critical infrastructure. Among these tools, NMAP (Network Mapper) stands out as a versatile and powerful utility for network discovery and security auditing.

This lecture explores NMAP as a comprehensive network scanning and reconnaissance tool, focusing on its application in active scanning scenarios. We will examine how NMAP enables security professionals to discover hosts, identify open ports, detect operating systems, enumerate services, and map network topologies. By understanding these capabilities, students will develop practical skills essential for network security assessment, vulnerability identification, and defensive planning.

The techniques discussed in this lecture are powerful and should be used responsibly. Always ensure you have proper authorisation before scanning any network that is not your own, as unauthorised scanning may violate legal and organisational policies.

## 1. NMAP Tool and Its Features

### 1.1 What is NMAP?

NMAP (Network Mapper) is an open-source utility for network discovery and security auditing. Originally developed by Gordon Lyon (also known as Fyodor Vaskovich) in 1997, NMAP has evolved into a comprehensive suite of tools for network exploration and security assessment (Lyon, 2008). The tool was designed to rapidly scan large networks, although it works equally well against single hosts.

According to Messier (2015, p.78), "NMAP is considered the de facto standard for port scanning and has been featured in numerous films, including The Matrix Reloaded, where Trinity uses NMAP to discover a vulnerable SSH server."

### 1.2 Core Features of NMAP

NMAP provides a wide range of features that make it an essential tool in a security professional's arsenal:

1. **Host Discovery**: Identifies active devices on a network
2. **Port Scanning**: Determines which ports are open, closed, or filtered
3. **Service Detection**: Identifies applications and versions running on open ports
4. **Operating System Detection**: Determines the operating system and hardware characteristics of network devices
5. **Scriptable Interaction**: Utilises the Nmap Scripting Engine (NSE) for advanced vulnerability detection and network discovery
6. **Output Flexibility**: Provides multiple formats for reporting and analysis
7. **Protocol Support**: Works with TCP, UDP, SCTP, and IP protocols
8. **Timing Controls**: Offers granular control over scanning speed and aggressiveness
9. **Evasion and Spoofing**: Includes mechanisms to bypass firewall and IDS/IPS systems
10. **IPv6 Support**: Full functionality for both IPv4 and IPv6 scanning

### 1.3 NMAP Architecture

NMAP operates through several key components:

| Component | Function |
|-----------|----------|
| Core Engine | Manages the scanning process and coordinates other modules |
| Host Discovery | Identifies active hosts on the network |
| Port Scanning Engine | Determines the state of ports on target systems |
| Service and Version Detection | Identifies services running on open ports |
| OS Detection Engine | Fingerprints operating systems |
| Nmap Scripting Engine (NSE) | Provides extensibility through Lua scripts |
| Output Engine | Formats and presents scan results |

This modular architecture allows NMAP to perform complex network reconnaissance tasks efficiently and flexibly (McNab, 2016).

## 2. Using NMAP to Scan Different Types of Networks

NMAP can be adapted to scan various network environments, from small local networks to large enterprise infrastructures.

### 2.1 Local Area Networks (LANs)

For LAN scanning, NMAP typically employs ARP requests to discover hosts because ARP operates at Layer 2 of the OSI model, making it faster and more reliable for local networks. Gordon (2020) explains that on a LAN, a basic NMAP scan might look like:

```
nmap -sn 192.168.1.0/24
```

This command performs a ping scan of all 254 possible hosts on the 192.168.1.0/24 subnet without port scanning, providing a quick inventory of active devices.

### 2.2 Wide Area Networks (WANs)

When scanning across wider networks where ARP is not available, NMAP relies on ICMP, TCP, and UDP protocols for host discovery. According to Kim and Solomon (2018), scanning across a WAN requires more consideration of bandwidth limitations and potential security controls:

```
nmap -PE -PS22,80,443 -PA3389 -PU161 -T2 10.0.0.0/16
```

This command uses a combination of ICMP echo requests (`-PE`), TCP SYN packets to common ports (`-PS22,80,443`), TCP ACK packets (`-PA3389`), and UDP packets (`-PU161`) with a conservative timing template (`-T2`) to discover hosts across a large address space.

### 2.3 Wireless Networks

Wireless networks present unique challenges for scanning. While NMAP itself doesn't directly capture wireless traffic, it can be used in conjunction with wireless adapters in monitor mode to scan wireless clients once their IP addresses are known. As noted by Basu (2019), NMAP can be combined with tools like Aircrack-ng or Wireshark to perform comprehensive wireless network assessments.

### 2.4 Cloud Environments

Scanning cloud infrastructure requires special consideration of cloud provider policies. Many providers may interpret unauthorised scanning as a potential attack. Diogenes and Ozkaya (2018) emphasise that when scanning cloud environments, users should:

1. Review cloud provider terms of service
2. Obtain necessary permissions
3. Focus scans on specific instances rather than entire ranges
4. Consider using provider-specific security assessment tools alongside NMAP

A typical cloud instance scan might look like:

```
nmap -A -T4 -v cloud-instance-ip
```

## 3. Active Scanning with NMAP

### 3.1 Understanding Active vs. Passive Scanning

Network scanning techniques fall into two general categories:

| Active Scanning | Passive Scanning |
|-----------------|------------------|
| Sends packets to target systems | Only observes existing network traffic |
| Provides comprehensive, real-time data | Limited to observable traffic |
| Can detect inactive services and ports | Cannot detect services not in use |
| Leaves traces in logs and may trigger alerts | Does not generate additional traffic |
| May impact network performance | No impact on network performance |
| Can potentially disrupt sensitive systems | No risk of disruption |

As Oriyano (2016) explains, "Active scanning deliberately engages with target systems to elicit responses that reveal information about their configuration and security posture."

### 3.2 NMAP's Active Scanning Techniques

NMAP primarily employs active scanning techniques, including:

1. **TCP Connect Scan** (`-sT`): Completes the TCP three-way handshake with each target port
2. **SYN Scan** (`-sS`): Sends TCP SYN packets but doesn't complete connections
3. **UDP Scan** (`-sU`): Sends UDP packets to detect open UDP services
4. **FIN, XMAS, and NULL Scans** (`-sF`, `-sX`, `-sN`): Uses specially crafted TCP packets to bypass simple filters
5. **ACK Scan** (`-sA`): Helps map firewall rulesets by determining filtering status
6. **Window Scan** (`-sW`): Detects subtle differences in RST packets returned from closed ports
7. **RPC Scan** (`-sR`): Identifies RPC services and their program numbers
8. **List Scan** (`-sL`): Simply lists targets to scan without sending packets
9. **Idle Scan** (`-sI`): Advanced technique using a zombie host for stealthy scanning

Each technique has specific use cases, advantages, and limitations. According to Stuttard and Pinto (2018), "The SYN scan (`-sS`) has become NMAP's default and most popular scan option because it combines good speed and reliability with relative stealth."

### 3.3 Configuring Active Scans

The effectiveness of active scanning depends on proper configuration. Key parameters include:

- **Timing Templates** (`-T0` to `-T5`): Control scan speed and aggressiveness
- **Packet Rate** (`--min-rate`, `--max-rate`): Fine-tune packet transmission rates
- **Parallelism** (`--min-parallelism`, `--max-parallelism`): Adjust concurrent probes
- **Host Timeout** (`--host-timeout`): Set maximum time spent on a target
- **Scan Delay** (`--scan-delay`, `--max-scan-delay`): Control timing between probes

Engebretson (2013) recommends starting with more conservative timing options when scanning sensitive environments: "A timing template of T3 provides a good balance between speed and reliability without overwhelming most networks."

## 4. Identifying Open Ports with NMAP

### 4.1 Port Scanning Fundamentals

Port scanning is the process of connecting to TCP and UDP ports to determine their state. NMAP classifies ports into six states:

1. **Open**: An application is actively accepting connections
2. **Closed**: Accessible but no application is listening
3. **Filtered**: Firewall or filter prevents probes from reaching port
4. **Unfiltered**: Accessible but uncertain whether open or closed
5. **Open|Filtered**: Unable to determine if open or filtered
6. **Closed|Filtered**: Unable to determine if closed or filtered

Experienced security professionals understand that these port states provide valuable information about network defences. As Allen (2012) notes, "The pattern of open, closed, and filtered ports often reveals more about a network's security posture than just the presence of individual services."

### 4.2 Port Scanning Techniques

NMAP offers several port scanning techniques, each with different characteristics:

| Scan Type | Command | Advantages | Disadvantages |
|-----------|---------|------------|---------------|
| TCP Connect | `-sT` | Accurate, works with unprivileged users | Easily logged, slower |
| SYN Scan | `-sS` | Fast, relatively stealthy | Requires root/admin privileges |
| UDP Scan | `-sU` | Identifies UDP services | Slow, often unreliable |
| FIN Scan | `-sF` | May bypass simple firewalls | Cannot distinguish open from filtered on most systems |
| NULL Scan | `-sN` | May bypass simple firewalls | Cannot distinguish open from filtered on most systems |
| XMAS Scan | `-sX` | May bypass simple firewalls | Cannot distinguish open from filtered on most systems |
| ACK Scan | `-sA` | Good for mapping firewall rules | Doesn't identify open ports directly |

### 4.3 Port Selection and Ranges

NMAP allows flexible port selection:

- Scan specific ports: `-p 22,80,443`
- Scan a range of ports: `-p 1-1000`
- Scan all ports: `-p-`
- Scan most common ports: `--top-ports 1000`
- Scan specific UDP ports: `-sU -p 53,161,162`

According to Hutchins et al. (2017), "A targeted approach to port scanning—focusing on ports relevant to the assessment objectives—often yields more actionable results than indiscriminate scanning of all possible ports."

### 4.4 Interpreting Port Scan Results

Sample NMAP port scan output:

```
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
25/tcp   filtered smtp
80/tcp   open     http
443/tcp  open     https
3389/tcp closed   ms-wbt-server
```

Analysing this output:
- Open ports (21, 22, 80, 443) suggest active services
- Filtered port (25) indicates firewall or security controls
- Closed port (3389) shows the port is accessible but not in use

The pattern of open, closed, and filtered ports provides valuable insight into the target's security architecture and potential attack surface (Harris and Allen, 2019).

## 5. Operating System Detection with NMAP

### 5.1 OS Detection Methodology

NMAP's operating system detection (`-O` option) works by analysing differences in TCP/IP stack implementations. According to Vacca (2017), NMAP sends a series of packets to open and closed ports, then examines characteristics of the responses, including:

1. TCP Initial Sequence Number (ISN) generation
2. TCP options support and their order
3. IP ID sequence generation
4. Initial window size
5. ACK value
6. ICMP error message quoting
7. TCP timestamp option algorithms

NMAP compares these characteristics against its database of known OS fingerprints to determine the most likely operating system.

### 5.2 Improving OS Detection Accuracy

For optimal OS detection results, Shah and Mehtre (2015) recommend:

1. Ensure at least one open and one closed port are available
2. Use the `--osscan-guess` or `--osscan-limit` options for aggressive or limited scanning
3. Update NMAP regularly to maintain current fingerprint databases
4. Combine with version detection (`-sV`) for more accurate results
5. Use `--max-os-tries` to control retry attempts

A comprehensive OS detection scan might use:

```
nmap -O --osscan-guess -T4 target
```

### 5.3 Limitations of OS Detection

OS fingerprinting is not foolproof. McNab (2016) outlines several limitations:

1. Firewalls and security devices may filter or modify telltale packets
2. Network address translation (NAT) devices can obscure characteristics
3. Virtual machines or custom systems may exhibit non-standard behaviours
4. TCP/IP stack hardening or modifications can disguise the true OS
5. Multiple operating systems with similar network stacks may be difficult to distinguish

When NMAP is uncertain, it provides percentage-based confidence levels for its OS detection results.

## 6. Service and Version Detection with NMAP

### 6.1 Service Detection Methods

NMAP's service detection (`-sV` option) identifies applications listening on open ports through "banner grabbing" and targeted probes. This process involves:

1. Connecting to open ports
2. Sending various probe strings
3. Analysing responses against a database of service signatures
4. Determining the most likely service and version

According to Kim and Solomon (2018, p.203), "Service identification is critical in security assessment because vulnerabilities are typically specific to particular versions of services."

### 6.2 Configuring Version Detection

The intensity of version scanning can be adjusted using `--version-intensity` (0-9):

| Intensity | Description | Use Case |
|-----------|-------------|----------|
| 0 | Only uses port numbers for identification | Fastest but least accurate |
| 1-2 | Uses only light, unobtrusive probes | Quick scans with minimal impact |
| 3-6 | Uses a moderate number of probes | Good balance of speed and accuracy |
| 7-8 | Uses most available probes | Thorough scanning for security assessments |
| 9 | Uses all available probes | Exhaustive scanning for maximum accuracy |

Engebretson (2013) suggests that "an intensity level of 7 provides sufficient detail for most security assessments without excessive scanning time."

Additional version scanning options include:
- `--version-light`: Equivalent to intensity 2
- `--version-all`: Equivalent to intensity 9
- `--version-trace`: Shows detailed version scanning activity

### 6.3 Sample Service Detection Output

```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  https   Nginx 1.18.0 (Ubuntu)
```

This output provides valuable information about:
- Service types (SSH, HTTP, HTTPS)
- Specific implementations (OpenSSH, Apache, Nginx)
- Version numbers (8.2p1, 2.4.41, 1.18.0)
- Underlying platform details (Ubuntu)

Weidman (2014) emphasises that "this level of detail is essential for vulnerability correlation and exploitation during penetration testing."

## 7. Vulnerability Identification with NMAP

### 7.1 Nmap Scripting Engine (NSE)

The Nmap Scripting Engine (NSE) extends NMAP's functionality to include vulnerability scanning capabilities. According to Lyon (2008), NSE uses Lua scripts categorised into libraries:

| Script Category | Purpose | Example Scripts |
|-----------------|---------|-----------------|
| auth | Authentication credentials testing | http-auth, ftp-brute |
| broadcast | Network discovery via broadcasts | dns-service-discovery, dhcp-discover |
| default | Safe scripts run by default with -sC | http-title, ssh-hostkey |
| discovery | Network/service information gathering | http-headers, smb-enum-shares |
| dos | Denial of service testing | http-slowloris, smb-flood |
| exploit | Exploitation of vulnerabilities | http-shellshock, ms17-010 |
| external | Scripts that may send data to external services | http-virustotal, shodan-api |
| fuzzer | Fuzz testing scripts | dns-fuzz, http-form-fuzzer |
| intrusive | Scripts that might crash systems or be detected | http-sql-injection, oracle-brute |
| malware | Malware detection | http-malware-host, smb-vuln-cve-2017-7494 |
| safe | Non-intrusive scripts | ssl-cert, http-security-headers |
| version | Service version detection scripts | http-wordpress-enum, ssh2-enum-algos |
| vuln | Vulnerability detection | ssl-heartbleed, smb-vuln-ms17-010 |

### 7.2 Running Vulnerability Scans

To run NSE scripts for vulnerability detection:

```
nmap --script vuln target
```

For more targeted scans:

```
nmap --script ssl-heartbleed,http-vuln* -p 443,80 target
```

Gordon (2020) recommends combining vulnerability scanning with service detection:

```
nmap -sV --script vuln -p- target
```

### 7.3 Interpreting Vulnerability Results

Sample vulnerability scan output:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: VULNERABLE
|     Description:
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible. It accomplishes this by opening connections to
|       the target web server and sending a partial request, then sending subsequent headers
|       at regular intervals to keep the connections open.
|     
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|       http://ha.ckers.org/slowloris/
```

Security professionals should understand that while NMAP's vulnerability detection is useful, it has limitations. Stuttard and Pinto (2018) warn that "NMAP's vulnerability checks provide a good starting point but should be supplemented with dedicated vulnerability scanners for comprehensive assessment."

## 8. Network Topology Mapping with NMAP

### 8.1 Trace Route and Path Analysis

NMAP can map network topology using its built-in traceroute functionality:

```
nmap --traceroute target
```

According to Shah and Mehtre (2015), NMAP's traceroute differs from traditional implementations:

1. Uses TCP SYN packets by default rather than ICMP
2. Starts at a high TTL and works backwards to find the last few hops
3. Can use different protocols (TCP, UDP, ICMP) based on scan type
4. Works efficiently with multiple targets in parallel

### 8.2 Network Topology Discovery

For mapping larger networks, NMAP offers several techniques:

1. **Ping sweeping** to identify live hosts:
   ```
   nmap -sn 192.168.0.0/24
   ```

2. **Route tracing** to identify network paths:
   ```
   nmap --traceroute -sn 192.168.0.0/24
   ```

3. **ARP scanning** for local network mapping:
   ```
   nmap -PR -sn 192.168.0.0/24
   ```

Harris and Allen (2019) suggest combining these approaches with output formats that facilitate visualisation:

```
nmap -sn 192.168.0.0/24 -oX network_map.xml
```

The XML output can then be imported into visualisation tools like Zenmap (NMAP's GUI) or converted for use with network mapping software.

### 8.3 Advanced Topology Mapping

For more comprehensive network mapping, McNab (2016) recommends supplementing NMAP with dedicated network visualisation tools:

1. Convert NMAP results to formats compatible with tools like:
   - Maltego
   - Network Notepad
   - Neo4j (graph database)

2. Use the NSE script `broadcast-listener` to discover devices that respond to broadcast messages:
   ```
   nmap --script broadcast-listener
   ```

3. Combine with DNS enumeration to map network services:
   ```
   nmap --script dns-service-discovery
   ```

## 9. Practical Example: Active Network Scanning with NMAP

### 9.1 Scenario Definition

Let us consider a practical scenario: a security assessment of a small business network (192.168.1.0/24) comprising various servers, workstations, and network devices. The objective is to identify active hosts, open services, and potential vulnerabilities using NMAP's active scanning capabilities.

### 9.2 Reconnaissance and Planning

Before launching scans, it's important to establish:
- Scan scope and boundaries
- Timing and potential network impact
- Specific information objectives
- Legal and organisational authorisation

For this example, we assume proper authorisation has been obtained for the 192.168.1.0/24 network range.

### 9.3 Initial Network Discovery

First, we'll identify active hosts without port scanning:

```
# Discover active hosts using multiple methods
nmap -sn -PE -PP -PS21,22,23,25,80,443,3389 -PA80,443,3389 -n 192.168.1.0/24 -oA initial_discovery
```

This command:
- Uses ping scan (`-sn`) to avoid port scanning
- Employs ICMP echo and timestamp requests (`-PE`, `-PP`)
- Sends TCP SYN packets to common ports (`-PS21,22,23,25,80,443,3389`)
- Sends TCP ACK packets to common ports (`-PA80,443,3389`)
- Skips DNS resolution for speed (`-n`)
- Saves results in all formats (`-oA`)

Sample output:
```
Nmap scan report for 192.168.1.1
Host is up (0.0024s latency).
MAC Address: 00:1A:2B:3C:4D:5E (Network Router Inc.)

Nmap scan report for 192.168.1.10
Host is up (0.0056s latency).
MAC Address: 00:1A:2B:3C:4D:6F (Server Manufacturer)

Nmap scan report for 192.168.1.20
Host is up (0.0087s latency).
MAC Address: 00:1A:2B:3C:4D:7G (Workstation Vendor)
```

### 9.4 Targeted Port Scanning

Next, we'll perform detailed port scanning on discovered hosts:

```
# Comprehensive scan of identified hosts
nmap -sS -sV -O -p- --min-rate 1000 --max-retries 1 -n -iL active_hosts.txt -oA detailed_scan
```

This command:
- Uses SYN scanning for speed and relative stealth (`-sS`)
- Enables version detection (`-sV`)
- Attempts OS detection (`-O`)
- Scans all 65535 ports (`-p-`)
- Sets minimum packet rate (`--min-rate 1000`)
- Limits retries for speed (`--max-retries 1`)
- Disables DNS resolution (`-n`)
- Uses a list of active hosts (`-iL`)
- Saves results in all formats (`-oA`)

Sample output for one host:
```
Nmap scan report for 192.168.1.10
Host is up (0.0066s latency).
Not shown: 65526 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp   open  http        Apache httpd 2.4.41
443/tcp  open  https       Apache httpd 2.4.41
3306/tcp open  mysql       MySQL 8.0.27
MAC Address: 00:1A:2B:3C:4D:6F (Server Manufacturer)
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.0 - 5.4
```

### 9.5 Service Enumeration and Vulnerability Scanning

After identifying services, we'll conduct more detailed enumeration and vulnerability scanning:

```
# Service enumeration and vulnerability scanning
nmap -sV --version-intensity 7 --script "default,safe,vuln" -p 22,80,443,3306 192.168.1.10 -oA vuln_scan
```

This command:
- Performs thorough version detection (`-sV --version-intensity 7`)
- Runs default, safe, and vulnerability scripts
- Targets only discovered open ports
- Saves results in all formats (`-oA`)

Sample output for the web server:
```
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-enum: 
|   /admin/: Admin login page
|   /images/: Directory listing
|   /phpmyadmin/: phpMyAdmin
|_  /robots.txt: Robots file
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.1.10
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.1.10/login.php
|     Form id: login-form
|_    Form action: login.php
```

### 9.6 Network Topology Mapping

Finally, we'll map the network's topology:

```
# Network topology mapping
nmap --traceroute -sn 192.168.1.0/24 -oA network_topology
```

This command:
- Performs traceroute to all hosts (`--traceroute`)
- Uses ping scanning without port scanning (`-sn`)
- Saves results in all formats (`-oA`)

### 9.7 Analysis and Reporting

After completing the scans, we analyse the results to identify:

1. Network structure and segmentation
2. Active hosts and their roles
3. Open services and potential attack vectors
4. Vulnerable services requiring remediation
5. Unusual or unexpected findings

Weidman (2014) emphasises the importance of contextualising NMAP findings: "Raw scan results must be interpreted within the broader context of the organisation's security architecture, business requirements, and risk tolerance."

For this example, key findings might include:
- Unnecessary services running on critical servers
- Outdated software with known vulnerabilities
- Weak network segmentation allowing broad internal access
- Authentication services exposed to the network
- Web applications with potential security issues

## Conclusion

NMAP stands as one of the most versatile and powerful tools for network discovery and security assessment. Through active scanning techniques, security professionals can gain valuable insights into network topology, identify running services, detect potential vulnerabilities, and map attack surfaces. The capabilities explored in this lecture—from basic port scanning to advanced vulnerability detection—form the foundation of effective network security assessment.

Understanding how to properly configure NMAP for different environments and requirements is essential for balancing thoroughness with efficiency and minimising potential disruption. By mastering the techniques discussed, security professionals can conduct comprehensive network assessments, identify security weaknesses, and develop effective remediation strategies.

As networks continue to evolve in complexity, tools like NMAP remain indispensable for maintaining visibility into constantly changing environments. However, it's important to remember that technical tools are most effective when wielded with proper authorisation, ethical consideration, and professional judgement. Network scanning, like any security assessment activity, should always be conducted responsibly and in accordance with legal and organisational policies.

## References

Allen, L. (2012) *Advanced Penetration Testing for Highly-Secured Environments*. Birmingham: Packt Publishing.

Basu, K. (2019) *Wireless Network Security: Theories and Applications*. Cambridge: Cambridge University Press.

Diogenes, Y. and Ozkaya, E. (2018) *Cybersecurity – Attack and Defense Strategies*. Birmingham: Packt Publishing.

Engebretson, P. (2013) *The Basics of Hacking and Penetration Testing: Ethical Hacking and Penetration Testing Made Easy*. 2nd edn. Waltham: Syngress.

Gordon, A. (2020) *The Official CompTIA Security+ Student Guide (Exam SY0-601): 2020 Update*. London: CompTIA.

Harris, S. and Allen, L. (2019) *CompTIA CySA+ Practice Tests: Exam CS0-002*. Indianapolis: Wiley.

Hutchins, E., Cloppert, M. and Amin, R. (2017) *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*. Bethesda: Lockheed Martin Corporation.

Kim, D. and Solomon, M. (2018) *Fundamentals of Information Systems Security*. 3rd edn. Burlington: Jones & Bartlett Learning.

Lyon, G. (2008) *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning*. Sunnyvale: Nmap Project.

McNab, C. (2016) *Network Security Assessment: Know Your Network*. 3rd edn. Sebastopol: O'Reilly Media.

Messier, R. (2015) *Network Forensics*. Indianapolis: John Wiley & Sons.

Oriyano, S. (2016) *CEH v9: Certified Ethical Hacker Version 9 Study Guide*. Indianapolis: Sybex.

Shah, S. and Mehtre, B. (2015) 'An Overview of Vulnerability Assessment and Penetration Testing Techniques', *Journal of Computer Science and Technology*, 30(4), pp. 852-867.

Stuttard, D. and Pinto, M. (2018) *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws*. 2nd edn. Indianapolis: Wiley.

Vacca, J. (2017) *Computer and Information Security Handbook*. 3rd edn. Burlington: Morgan Kaufmann.

Weidman, G. (2014) *Penetration Testing: A Hands-On Introduction to Hacking*. San Francisco: No Starch Press.