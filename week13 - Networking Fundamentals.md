# Week 13 Lecture: Networking Fundamentals 

## Learning Objectives
By the end of this lecture, students should be able to:
1. Understand the basics of network addressing, including IPv4, IPv6, subnetting and CIDR
2. Explain how IP addresses are allocated hierarchically 
3. Describe the OSI and TCP/IP models and the role of each layer
4. Understand encapsulation and how data flows through a network
5. Explain key networking protocols like ARP, ICMP, DHCP and DNS

## Introduction 
Networking is a critical component of modern computing systems. Whether you're browsing the web, sending an email, or connecting to a remote server, networking protocols and standards make it all possible. In this lecture, we'll dive deep into some core networking concepts that every ethical hacker and computer scientist should know.

## 1. Network Addressing
At the heart of networking is the concept of addressing. Just like you need a mailing address to send a letter, computers need IP addresses to send data packets. Let's look at the two main types of IP addresses in use today.

### 1.1 IPv4 
IPv4 addresses are 32-bit numbers, typically written as four 8-bit decimal numbers separated by dots, like `192.168.0.1`. Here's how to understand an IPv4 address:

- It's divided into network and host portions based on the subnet mask 
- The network portion identifies the network the device is on
- The host portion uniquely identifies the device on that network
- Subnet masks also use dotted decimal notation, like `255.255.255.0`
- A `1` in the subnet mask indicates a network bit, a `0` indicates a host bit

For example, consider the address `192.168.0.15` with a subnet mask of `255.255.255.0`:

```
Address:   192.168.0.15
Subnet:    255.255.255.0
------------------------
Network:   192.168.0.0
Host:      0.0.0.15
```

This address is on the `192.168.0.0` network, and `.15` uniquely identifies the host on that network.

### 1.2 IPv6
IPv6 is the successor to IPv4, using 128-bit addresses to provide a much larger address space. An IPv6 address is written as eight groups of four hexadecimal digits, separated by colons:

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

Some key differences from IPv4:

- Leading zeros in a group can be omitted: `2001:db8:85a3:0:0:8a2e:370:7334` 
- Consecutive sections of all zeros can be replaced with `::`, but only once: `2001:db8:85a3::8a2e:370:7334`
- The network prefix is denoted with CIDR notation, like `/64` instead of a subnet mask

For example, the address `2001:db8:1234::/48` has a 48-bit network prefix of `2001:db8:1234` and a 80-bit interface identifier.

### 1.3 Subnetting and CIDR
Subnetting divides a network into smaller subnetworks, allowing for better network management and security. It's based on "borrowing" host bits to create additional network bits.

#### 1.3.1 CIDR
Classless Inter-Domain Routing (CIDR) is a method for specifying the number of network bits (the prefix length) in an IP address. It's written as the IP address followed by a slash and the number of network bits:
 
```
192.168.0.0/24
```

This `/24` indicates the first 24 bits are the network portion, corresponding to a subnet mask of `255.255.255.0`.

Common CIDR prefixes:
- `/8` : 255.0.0.0
- `/16` : 255.255.0.0 
- `/24` : 255.255.255.0
- `/32` : 255.255.255.255 (a single host)

#### 1.3.2 Subnetting Example
Subnetting allows us to divide a network into smaller chunks. For example, let's say we have the network `192.168.1.0/24` and we want to create two subnets.

1. Borrow 1 host bit to create 2 subnets (2^1 = 2).
2. The new subnet mask is 255.255.255.128 or /25.
3. The subnets are:
   - `192.168.1.0/25` (192.168.1.0 - 192.168.1.127)
   - `192.168.1.128/25` (192.168.1.128 - 192.168.1.255)

We can keep borrowing bits to create more subnets as needed.

## 2. IP Address Allocation
IP addresses are managed globally by the Internet Assigned Numbers Authority (IANA). But how do they get from IANA to your device? It follows a hierarchical allocation:

1. **IANA**: Manages the global pool of IP addresses. Allocates large blocks to RIRs.
2. **Regional Internet Registries (RIRs)**: Manage addresses for geographic regions (ARIN, RIPE, APNIC, LACNIC, AFRINIC). Allocate smaller blocks to LIRs/ISPs. 
3. **Local Internet Registries (LIRs) / Internet Service Providers (ISPs)**: Allocate addresses to customers in their network.
4. **End User**: Gets address allocation from their ISP for their devices.

This hierarchical system allows for efficient allocation and routing of IP addresses globally.

## 3. OSI Model
The Open Systems Interconnection (OSI) model is a conceptual framework that describes the functions of a networking system. It divides network communication into seven layers:

| Layer | Function | Protocols |
|-------|----------|-----------|
| 7. Application | High-level APIs, including resource sharing, remote file access | HTTP, FTP, SMTP, DNS |
| 6. Presentation | Translation of data between a networking service and an application; including character encoding, data compression and encryption/decryption | ASCII, MPEG, SSL, TLS  |
| 5. Session | Managing communication sessions, i.e. continuous exchange of information in the form of multiple back-and-forth transmissions between two nodes | RPC, PAP, SCP, SQL |
| 4. Transport | Reliable transmission of data segments between points on a network, including segmentation, acknowledgement and multiplexing | TCP, UDP, SPX |
| 3. Network | Structuring and managing a multi-node network, including addressing, routing and traffic control | IPv4, IPv6, ICMP, IPSEC, IGMP |
| 2. Data Link | Reliable transmission of data frames between two nodes connected by a physical layer | PPP, SLIP, SDLC, HDLC, ARP, CSLIP  |
| 1. Physical | Transmission and reception of raw bit streams over a physical medium | Ethernet, USB, Bluetooth, 802.11 |

### 3.1 Communication Between Layers
Each layer communicates with the layer directly above and below it:

- **Downward**: A layer encapsulates data from the layer above into a protocol data unit (PDU), adding its own header information. This PDU is then passed down to the next lower layer.
- **Upward**: When a layer receives a PDU from the layer below, it strips off its own header information, and passes the remaining data up to the layer above.

This process of encapsulation and decapsulation allows each layer to provide services to the layer above while using the services of the layer below.

### 3.2 Protocol Data Units
As data moves through the OSI model, each layer adds its own header (and sometimes trailer) information. The term for the data at each layer is a protocol data unit (PDU):

| Layer | PDU | Headers Added |
|-------|-----|---------------|
| Application | Data | - |
| Presentation | Data | - |
| Session | Data | - |
| Transport | Segment | Source port, Destination port, Sequence number, Acknowledgment number |
| Network | Packet | Source IP, Destination IP | 
| Data Link | Frame | Source MAC, Destination MAC, FCS |
| Physical | Bits | - |

## 4. TCP/IP Model 
The TCP/IP model (Transmission Control Protocol/Internet Protocol) is a more concise version of the OSI model. It's the model used in the modern Internet. 

### 4.1 TCP/IP Layers

| Layer | Protocols |
|-------|-----------|
| Application | HTTP, FTP, Telnet, SMTP, DNS |
| Transport | TCP, UDP |
| Internet | IP, ICMP, ARP, RARP |
| Network Interface | Ethernet, Wi-Fi, PPP |

### 4.2 Data Flow
When an application sends data using TCP/IP, here's what happens:

1. The data is passed from the Application layer to the Transport layer.
2. The Transport layer segments the data and adds a header to each segment, creating a segment.
3. The segment is passed to the Internet layer, which packages it into a packet, adding its own IP header. 
4. The packet is passed to the Network Interface layer, which frames the packet with its own header and trailer, creating a frame.
5. The frame is then transmitted over the physical network.

When a device receives data, the process is reversed:

1. The Network Interface layer receives the frame, checks it for errors, and strips off the frame header and trailer.
2. The resulting packet is passed up to the Internet layer, which examines the IP header and passes it up to the Transport layer.
3. The Transport layer reads the segment header and passes the data to the appropriate application based on the port number.
4. The Application layer receives the data.

### 4.3 Encapsulation Example
Let's say you're sending an HTTP request. Here's how that data would be encapsulated:

```
HTTP Request
GET /index.html HTTP/1.1
Host: www.example.com

TCP Segment
Source Port: 12345
Destination Port: 80
Sequence Number: 1
Acknowledgment Number: 1
Flags: SYN
Data: GET /index.html HTTP/1.1
      Host: www.example.com

IP Packet 
Source IP: 192.168.1.100
Destination IP: 93.184.216.34
Protocol: TCP
Data: <TCP Segment>

Ethernet Frame
Source MAC: 00:11:22:33:44:55  
Destination MAC: AA:BB:CC:DD:EE:FF
EtherType: IPv4 
Data: <IP Packet>
FCS: 123456
```

## 5. Device Communication
When two devices on a network want to communicate, they need each other's IP address and MAC address. Here's the typical process:

1. The source device has the destination IP address (either manually configured or through DNS).
2. The source broadcasts an ARP request, asking "Who has IP address X.X.X.X? Tell Y.Y.Y.Y" 
3. The destination device sees the ARP request and replies with its MAC address.
4. The source caches the IP-MAC mapping and can now send frames directly to the destination's MAC address.

This process is an example of encapsulation in action:

- The Application layer has the destination IP address
- It sends data down to the Transport layer
- The Transport layer segments the data and passes it to the Network (IP) layer
- The IP layer constructs a packet with the destination IP
- The Data Link (Ethernet) layer doesn't know how to reach the destination IP, so it broadcasts an ARP request
- The destination replies with its MAC address
- The Ethernet layer can now construct frames with the proper source and destination MAC addresses

## 6. Key Networking Protocols

### 6.1 ARP 
Address Resolution Protocol (ARP) is used to discover the link layer address (MAC address) associated with a given internet layer address (IP address).

- An ARP request is broadcast, asking "Who has IP X.X.X.X?"
- The device with that IP responds with its MAC address
- The requestor caches the IP-MAC mapping for future use

### 6.2 ICMP
Internet Control Message Protocol (ICMP) is used by network devices to send error messages and operational information.

Common ICMP messages:
- Echo Request/Reply (used by ping)
- Destination Unreachable
- Time Exceeded
- Redirect

### 6.3 DHCP
Dynamic Host Configuration Protocol (DHCP) is used to automatically assign IP addresses to devices on a network.

DHCP process:
1. Client broadcasts a DHCP Discover message
2. DHCP server responds with a DHCP Offer
3. Client requests the offered address with a DHCP Request
4. Server acknowledges with a DHCP Acknowledgement

The DHCP server can also provide additional configuration details like subnet mask, default gateway, DNS servers, etc.

### 6.4 DNS  
Domain Name System (DNS) is used to translate domain names (like www.example.com) into IP addresses.

DNS hierarchy:
- Root DNS Servers
- Top-Level Domain (TLD) Servers (.com, .org, etc)
- Authoritative DNS Servers (for specific domains)

When a client wants to look up a domain name:
1. It queries its local DNS server (resolver)
2. The resolver queries the root servers to find the TLD server
3. It then queries the TLD server to find the authoritative server
4. Finally, it queries the authoritative server to get the IP address

The resolver will cache these results to speed up future lookups.

## Conclusion
In this lecture, we've covered the fundamentals of networking that every ethical hacker should know. We've looked at IP addressing, allocation, the OSI and TCP/IP models, encapsulation, and key protocols like ARP, ICMP, DHCP and DNS. 

Understanding these concepts is crucial for analyzing network traffic, identifying vulnerabilities, and securing network communications. In the next lecture, we'll build on these foundations to explore more advanced networking concepts and tools used in ethical hacking.

## References
- Kurose, J.F. & Ross, K.W. (2017). Computer Networking: A Top-Down Approach (7th Edition). Pearson.
- Stallings, W. (2016). Network Security Essentials: Applications and Standards (6th Edition). Pearson.
- RFC 791 - Internet Protocol. https://tools.ietf.org/html/rfc791 
- RFC 793 - Transmission Control Protocol. https://tools.ietf.org/html/rfc793
- RFC 2131 - Dynamic Host Configuration Protocol. https://tools.ietf.org/html/rfc2131
- RFC 1034 - Domain Names - Concepts and Facilities. https://tools.ietf.org/html/rfc1034
