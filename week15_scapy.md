# Week 15 - Scapy

Scapy is a powerful Python library used for packet manipulation.  It allows you to craft, send, sniff, and dissect network packets.  This makes it an incredibly versatile tool for ethical hacking, network testing, and security research.  

* Think of it as a low-level, programmable way to interact with network traffic, giving you fine-grained control.

**Key Features of Scapy:**

*   **Packet Crafting:** Scapy lets you create packets of almost any type (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, etc.). You can customize every field in the packet headers, allowing you to simulate various network conditions or craft malicious packets for testing purposes.
*   **Packet Sniffing:** Scapy can capture network traffic (sniffing) on a given interface. It can filter packets based on specific criteria, making it easier to analyze relevant traffic.
*   **Packet Dissection:** Scapy can dissect captured packets, breaking down the headers and payloads into their individual fields.  This lets you understand the structure and content of network traffic.
*   **Interactive Mode:** Scapy has an interactive mode where you can experiment with packets in real-time. This is great for learning and testing different scenarios.
*   **Programmable:** Because Scapy is a Python library, you can write scripts to automate complex network tasks, such as network discovery, vulnerability scanning, or fuzzing.

**Main Use Cases in Ethical Hacking:**

1.  **Network Discovery:** Scapy can be used to discover hosts on a network.  You can send ARP requests to identify active devices or use other techniques like ping sweeps.  It's a building block for network mappers.

2.  **Vulnerability Scanning:** Scapy allows you to craft specific packets to test for vulnerabilities in network devices or services. For example, you can send malformed packets to see how a target system responds.

3.  **Penetration Testing:**  Scapy is invaluable in penetration testing. You can use it to:

    *   **Spoofing:** Create spoofed packets (e.g., ARP poisoning) to redirect traffic or perform man-in-the-middle attacks (for testing purposes, of course, and only with permission).
    *   **Firewall Testing:**  Craft packets to test firewall rules and identify weaknesses.
    *   **Intrusion Detection/Prevention System (IDS/IPS) Evasion:**  Create packets designed to bypass IDS/IPS systems (again, for testing and improving security, with authorization).
    *   **Fuzzing:** Generate a large number of malformed or unexpected packets to test the robustness of a target system.

4.  **Network Probing:** Scapy can be used to gather information about network services and protocols.  You can send specific requests (e.g., DNS queries) to identify the services running on a target system.

5.  **Packet Analysis:** Scapy's dissection capabilities are helpful for analyzing network traffic captures (PCAP files).  You can write scripts to extract specific information or identify suspicious patterns.

6.  **Custom Tool Development:** Because it's a Python library, Scapy enables you to create custom network tools tailored to specific tasks.  This is a huge advantage for automating and extending its functionality.

**Example (ARP Ping):**

```python
from scapy.all import *

# Create an ARP request
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24") # Broadcast ARP

# Send and receive responses
ans, unans = srp(arp_request, timeout=2, inter=0.1) # Send and receive

# Print the results
for sent, received in ans:
    print(f"{received.psrc} is up")
```


Let's delve deeper into ARP requests and the Scapy code snippet.

**What is an ARP Request?**

ARP stands for Address Resolution Protocol.  It's a fundamental protocol used on local area networks (LANs) to map IP addresses to MAC addresses.  Here's why it's necessary:

*   **IP Addresses vs. MAC Addresses:**  IP addresses are logical addresses used at the network layer (Layer 3 of the OSI model). They allow devices on different networks to communicate. MAC addresses (Media Access Control addresses) are physical addresses used at the data link layer (Layer 2). They're unique identifiers assigned to network interfaces (like your computer's Ethernet or Wi-Fi card).

*   **The Problem:** When a device wants to send data to another device on the *same* LAN, it knows the destination's IP address. But Ethernet (the most common LAN technology) uses MAC addresses for communication.  So, the sending device needs a way to find the MAC address associated with the destination IP address.  This is where ARP comes in.

*   **The Solution:**  The sending device broadcasts an ARP request.  This request asks, "Who has IP address X?"  All devices on the LAN receive the broadcast.  The device with IP address X responds with an ARP reply, saying, "I have IP address X, and my MAC address is Y."  The sending device then stores this IP-MAC mapping in its ARP cache, so it doesn't have to repeat the ARP request every time it wants to communicate with that device.

**Detailed Explanation of the Scapy ARP Ping Code:**

```python
from scapy.all import *

# 1. Create an ARP request
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")

# 2. Send and receive responses
ans, unans = srp(arp_request, timeout=2, inter=0.1)

# 3. Print the results
for sent, received in ans:
    print(f"{received.psrc} is up")
```

What is an ARP Request?

ARP stands for Address Resolution Protocol.  It's a fundamental protocol used on local area networks (LANs) to map IP addresses to MAC addresses.  Here's why it's necessary:

IP Addresses vs. MAC Addresses:  IP addresses are logical addresses used at the network layer (Layer 3 of the OSI model). They allow devices on different networks to communicate. MAC addresses (Media Access Control addresses) are physical addresses used at the data link layer (Layer 2). They're unique identifiers assigned to network interfaces (like your computer's Ethernet or Wi-Fi card).

The Problem: When a device wants to send data to another device on the same LAN, it knows the destination's IP address. But Ethernet (the most common LAN technology) uses MAC addresses for communication.  So, the sending device needs a way to find the MAC address associated with the destination IP address.  This is where ARP comes in.

The Solution:  The sending device broadcasts an ARP request.  This request asks, "Who has IP address X?"  All devices on the LAN receive the broadcast.  The device with IP address X responds with an ARP reply, saying, "I have IP address X, and my MAC address is Y."  The sending device then stores this IP-MAC mapping in its ARP cache, so it doesn't have to repeat the ARP request every time it wants to communicate with that device.

Detailed Explanation of the Scapy ARP Ping Code:

**Line-by-Line Breakdown:**

1.  **`from scapy.all import *`:** This line imports all the classes and functions from the Scapy library. The `*` is generally discouraged in production code but is common in interactive use and examples.

2.  **`arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")`:** This is the core of the ARP request creation.

    *   `Ether(dst="ff:ff:ff:ff:ff:ff")`: This creates an Ethernet frame.  `dst="ff:ff:ff:ff:ff:ff"` sets the destination MAC address to the broadcast address.  This means the frame will be sent to all devices on the LAN.

    *   `/`:  The `/` operator in Scapy is used for packet layering.  It combines the Ethernet frame with the ARP packet.

    *   `ARP(pdst="192.168.1.0/24")`: This creates the ARP packet. `pdst="192.168.1.0/24"` sets the target IP address (the IP address you're asking about) to the network address 192.168.1.0/24.  Scapy will automatically send ARP requests for each IP address in the specified subnet (from 192.168.1.1 to 192.168.1.254).

3.  **`ans, unans = srp(arp_request, timeout=2, inter=0.1)`:** This line sends the ARP request and waits for responses.

    *   `srp()`: This function stands for "send and receive packets" at layer 2. It sends the crafted `arp_request` and listens for replies.
    *   `timeout=2`:  Sets a timeout of 2 seconds.  Scapy will wait for a maximum of 2 seconds for responses.
    *   `inter=0.1`: Sets the interval between sending each ARP request to 0.1 seconds. This helps avoid overwhelming the network.
    *   `ans, unans`: `srp()` returns two lists: `ans` contains the packets that were answered (devices that responded to the ARP request), and `unans` contains the packets that were not answered.

4.  **`for sent, received in ans:`:** This loop iterates through the answered packets.

    *   `sent`: The packet that was sent.
    *   `received`: The packet that was received in response.

5.  **`print(f"{received.psrc} is up")`:** This line prints the IP address of the responding device.  `received.psrc` extracts the source IP address from the received ARP reply.  The `f-string` formatting makes it easy to embed the IP address in the output.

**In Summary:**

The code creates an ARP request packet, broadcasts it to the specified network, listens for ARP replies, and then prints the IP addresses of the devices that responded, indicating that they are "up" or active on the network.  This is a basic but essential technique for network discovery.


## Networking Concepts in Scapy

### What is an Ethernet Frame?

An Ethernet frame is the fundamental unit of data transmission on an Ethernet network (which is the most common type of local area network or LAN).  

* Think of it as the "envelope" that carries your data across the network.  It has a specific structure, containing various headers and a payload.   

#### Structure of an Ethernet Frame (Simplified):

 `Preamble and Start Frame Delimiter (SFD)`: These are a few bytes at the beginning of the frame used for synchronization between the sending and receiving devices.  They help the receiver recognize the start of a new frame.   

`Destination MAC Address`: A 6-byte field containing the MAC address of the device that should receive the frame.

 `Source MAC Address`: A 6-byte field containing the MAC address of the device that sent the frame.   

`EtherType/Length`: A 2-byte field.  In older Ethernet frames, it indicated the length of the data payload. In modern Ethernet frames (using the 802.3 standard), it's the EtherType, which identifies the protocol of the payload (e.g., 0x0806 for ARP, 0x0800 for IPv4).   

` Payload (Data)`: This is the actual data being transmitted.  In the case of an ARP request, the ARP packet itself is the payload of the Ethernet frame.   

`Frame Check Sequence (FCS)`: A 4-byte field containing a checksum.  The sending device calculates this checksum based on the frame's contents, and the receiving device recalculates it upon receiving the frame.  If the checksums match, it indicates that the frame was transmitted without errors.   

### Why is an Ethernet Frame Used in an ARP Request?

`Here's the key:`  Ethernet networks use MAC addresses for communication at the data link layer (Layer 2 of the OSI model).  

* Therefore, every communication over Ethernet, including ARP requests, must be encapsulated within an Ethernet frame.

The ARP request itself is a separate packet (containing information like the target IP address), but it doesn't travel across the network on its own. It needs to be carried within an Ethernet frame.

Here's how it works in the context of an ARP request:

* The Sending Device Creates the ARP Packet: The sending device wants to find the MAC address associated with a specific IP address.  It creates an ARP request packet. This packet contains the target IP address (the IP address it wants to resolve).

* The Sending Device Creates the Ethernet Frame: The sending device then creates an Ethernet frame.   

* The destination MAC address of the Ethernet frame is set to the broadcast MAC address (ff:ff:ff:ff:ff:ff). 

    * This ensures that all devices on the LAN will receive the frame.

* The source MAC address of the Ethernet frame is set to the MAC address of the sending device's network interface.

* The EtherType field is set to 0x0806, indicating that the payload is an ARP packet.

* The payload of the Ethernet frame is the ARP request packet that was created in the previous step.

`The Ethernet Frame is Transmitted:` The sending device transmits the complete Ethernet frame onto the network.

 `Devices on the LAN Receive the Frame:` Every device on the LAN receives the Ethernet frame because it was sent to the broadcast MAC address.   

`Devices Process the Frame:` Each device examines the Ethernet frame.  They check the destination MAC address.  Because it's the broadcast address, all devices process the frame further.

`Devices Process the ARP Packet:` The devices check the EtherType to see that it's an ARP packet. They then examine the ARP request inside the frame.  Only the device whose IP address matches the target IP address in the ARP request will respond.   

`The Responding Device Sends an ARP Reply`: The device with the matching IP address creates an ARP reply packet containing its MAC address.  It then encapsulates this ARP reply packet within an Ethernet frame (with the destination MAC address set to the MAC address of the original requester) and sends it back to the requesting device.

`In summary`: The Ethernet frame is the carrier.  It's the container that allows the ARP request (or any other network data) to be transmitted across the Ethernet network.  Without the Ethernet frame, the ARP request would not be able to reach its destination.


## The difference between an ethernet frame and a network packet

In the realm of computer networks and data transmission, an Ethernet frame and a network packet are related but not quite the same. 

### Ethernet Frame:
- **Definition**: It's a data unit at the Data Link Layer (Layer 2) of the OSI model.
- **Purpose**: Used for physical transmission of data across an Ethernet network.
- **Structure**: Consists of a preamble, destination MAC address, source MAC address, EtherType/length, payload, and a frame check sequence (FCS).

### Network Packet:
- **Definition**: It's a data unit at the Network Layer (Layer 3) of the OSI model.
- **Purpose**: Encapsulates data for routing through an internetwork (i.e., across multiple networks).
- **Structure**: Includes a network layer header (like an IP header with source and destination IP addresses) and a payload (often containing the data encapsulated in an Ethernet frame).

In simple terms, an Ethernet frame is used to transfer data within the same network, while a network packet is used to transfer data between different networks. Think of the Ethernet frame as a local delivery van and the network packet as an international courier service. 🚚 ✈️




