# Lecture 13 - Intreoduction to Networking and Wireshark

## Introduction

WireShark is a network protocol analyzer that captures and displays the data traveling back and forth on a network. It can be used to capture the TCP three-way handshake between two systems. 

The three packets of the TCP three-way handshake will be displayed in the Wireshark capture, showing the SYN, SYN-ACK, and ACK packets. 

The captured packets can be analyzed to see the details of the TCP three-way handshake, including the sequence numbers, window sizes, and other connection parameters.

## Typical Network communication pattern

- A SYN packet is a request to start a TCP connection i.e. start a session
- A SYN-ACK packet is a response to the SYN packet, and is a request to start a TCP connection
- An ACK packet is a response to the SYN-ACK packet, and is a request to start a TCP connection

These three packets are known as the TCP three-way handshake

Using wireshark we can capture the TCP three-way handshake between two systems and analyze the packets to see the details of the handshake and the connection parameters.

## TCP three-way handshake

- The three-way handshake is a method used in a TCP/IP network to create a connection between a local host/client and server

- It is a three-step method that requires both the client and server to exchange SYN and ACK (acknowledgment) packets before actual data communication begins

The three-way handshake is designed so that:

- both ends can initiate and negotiate the connection at the same time
- both ends can acknowledge the receipt of the other end's packets
- both ends can agree on the connection parameters
- both ends can agree on the sequence numbers used to start the session
- both ends can agree on the window size used to control the flow of data

### Port numbers and thier role

Port numbers represent the endpoints of logical connections between two devices. Conceptually a port could be thought of as a pipe that data flows through. The pipe has two ends, one for each device. The port number is used to uniquely identify the pipe for each device. 

There are two types of ports: `well-known ports` and `dynamic ports`. 

- Well-known ports are reserved for specific applications and services, and are assigned by the Internet Assigned Numbers Authority (IANA). 

- Dynamic ports are used for temporary connections and are assigned by the operating system. 

In total there are 65,535 ports available for use. Ports are divided into three ranges: well-known ports (0-1023), registered ports (1024-49151), and dynamic ports (49152-65535).

Some of the well-known ports include:

- Port 21: FTP (File Transfer Protocol)
- Port 22: SSH (Secure Shell)
- Port 23: Telnet
- Port 25: SMTP (Simple Mail Transfer Protocol)
- Port 53: DNS (Domain Name System)
- Port 80: HTTP (Hypertext Transfer Protocol)
- Port 110: POP3 (Post Office Protocol version 3)
- Port 143: IMAP (Internet Message Access Protocol)
- Port 443: HTTPS (Hypertext Transfer Protocol Secure)

A port number is mapped to a particular service running on a computer. 

For example, port 80 is mapped to the HTTP service, which is used to serve web pages. 

- When a client wants to access a web page, it sends a request to the server on port 80. 

- The server receives the request and sends the web page back to the client on the same port.

Interstingly enough port 80 for example is the default port for HTTP, but it is not the only port that can be used for HTTP. In fact, any port can be used for any service, as long as both the client and server agree on the port number. This is why port numbers are important in networking, as they allow multiple services to run on the same computer and communicate with each other. 

- If pport 80 is available it means that there is a web server running on the computer. The web server is listening on port 80 for incoming requests. 
- Typically on port 8 0 everything is sent in plain text. 
- If the web server is running on port 443, it means that the web server is using HTTPS, which is a secure version of HTTP that encrypts the data being sent between the client and server.

Port are typically used to:

- Identify specific applications or services running on a computer
- Allow multiple applications or services to run on the same computer
- Allow multiple applications or services to communicate with each other

Ports are similar to telephone extensions in that they allow multiple services to run in the same environment (computer) and communicate with each other. 

For example, if you have a web server running on a computer, it will listen on port 80 for incoming requests. 

- If you have an email server running on the same computer, it will listen on port 25 for incoming email. 

Each service has its own port number, which allows the computer to route incoming data to the correct service.

## What is a packet?

A packet is a unit of data that is transmitted over a network. It consists of a header and a payload. The header contains information about the packet, such as the source and destination addresses, the size of the payload, and the type of data contained in the payload. 

The payload contains the actual data being transmitted. Packets are used to send data between devices on a network, such as computers, routers, and servers. 

They are the basic building blocks of network communication, and are used to transmit data over the Internet, local area networks (LANs), and wide area networks (WANs).

In general a network packet contains the following information:

- Source address: The IP address of the device that sent the packet
- MAC address: The hardware address of the device that sent the packet
- TTL (Time to Live): The maximum number of hops the packet can take before being discarded
- Destination address: The IP address of the device that is intended to receive the packet
- Protocol: The type of data contained in the packet, such as TCP, UDP, or ICMP
- Port numbers: The port numbers used to identify the source and destination applications
- Payload: The actual data being transmitted in the packet

Packets are transmitted over a network using a variety of protocols, such as TCP (Transmission Control Protocol), UDP (User Datagram Protocol), and ICMP (Internet Control Message Protocol). 

These protocols define how packets are formatted, transmitted, and received by devices on the network.

For example, TCP is a connection-oriented protocol that guarantees the delivery of data in the order it was sent, while UDP is a connectionless protocol that does not guarantee the delivery of data.

A packet has a maximum size, known as the maximum transmission unit (MTU), which is determined by the network hardware and software. If a packet is too large to be transmitted over the network, it is fragmented into smaller packets that can be transmitted individually and reassembled at the destination.

This process is known as packet fragmentation. 

Typically packets are between 64 and 1500 bytes in size, depending on the network technology being used.

So a 1GB file that is being sent over the network will be broken down into smaller packets, each containing a portion of the file. 

These packets are then transmitted over the network and reassembled at the destination to recreate the original file. This process allows large files to be transmitted efficiently over the network, as it reduces the amount of data that needs to be transmitted at one time.

A packet encapsulates all layers of the OSI model, from the physical layer to the application layer. This means that a packet contains information about the source and destination devices, the network addresses, the type of data being transmitted, and the application that is sending or receiving the data. 

This information is used by the network devices to route the packet to the correct destination and deliver the data to the correct application.

## OSI model

The OSI model is aconceptual framework that standardizes the functions of a telecommunication or computing system into seven abstraction layers. A packet encapsulates all layers of the OSI model, from the physical layer to the application layer. 

This means that a packet contains information about the source and destination devices, the network addresses, the type of data being transmitted, and the application that is sending or receiving the data. This information is used by the network devices to route the packet to the correct destination and deliver the data to the correct application.

Here is a summary table of the OSI model:

| Layer | Name | Function | Protocols | Data Unit |
|-------|------|----------|-----------|-----------|
| 7 | Application | Network process to application | HTTP, SMTP, FTP | Data |
| 6 | Presentation | Data representation and encryption | SSL, TLS | Data |
| 5 | Session | Interhost communication | NetBIOS, PPTP | Data |
| 4 | Transport | End-to-end connections and reliability | TCP, UDP | Segment |
| 3 | Network | Path determination and logical addressing | IP, ICMP | Packet |
| 2 | Data Link | Physical addressing | Ethernet, PPP | Frame |
| 1 | Physical | Media, signal and binary transmission | Ethernet, Wi-Fi | Bit |

So a single network packet in theory has to pass through all seven layers of the OSI model before it can be transmitted over the network. Each layer adds its own header and footer to the packet, which contains information about the layer and the data being transmitted. 

This process is known as encapsulation, and it allows the packet to be transmitted over the network and delivered to the correct destination.

Not much attention is paid to layers 5 and 6 in the OSI model, as they are not as relevant to network communication as the other layers. Layers 5 and 6 are responsible for establishing, maintaining, and terminating connections between devices on a network, and for encrypting and decrypting data being transmitted. 

- These functions are important for secure communication between devices, but are not as critical to network communication as the other layers.

A very important layer is the transport layer, which is responsible for end-to-end connections and reliability. The transport layer is where the TCP and UDP protocols operate, which are used to establish connections between devices and ensure the reliable delivery of data. 

TCP is a connection-oriented protocol that guarantees the delivery of data in the order it was sent, while UDP is a connectionless protocol that does not guarantee the delivery of data. These protocols are used to transmit data between devices on a network and ensure that the data is delivered correctly and efficiently.

## PCAP files

PCAP stands for Packet Capture, and is a file format used by network analyzers to capture and analyze network traffic. A PCAP file contains the raw data packets captured from the network, as well as the metadata associated with the packets, such as the source and destination addresses, the protocol used, and the size of the packet. 

PCAP files are used to troubleshoot network communication issues, analyze network traffic, and monitor network performance. They can be used to capture and analyze the data packets of various network protocols, including TCP, UDP, HTTP, and others. 

PCAP files can be captured from both wired and wireless networks, and can be used to analyze the data packets of both local and remote networks.

A PCAP file is a packet capture file that contains data captured from a network. It is used by network analyzers, such as Wireshark, to analyze the data packets traveling on the network. 

A PCAP file contains the raw data packets captured from the network, as well as the metadata associated with the packets, such as the source and destination addresses, the protocol used, and the size of the packet.

A 100MB PCAP file, for example, contains thousands of data packets captured from the network. Each packet contains information about the source and destination addresses, the protocol used, the size of the packet, and other metadata. 

- This information can be used to analyze the network traffic, troubleshoot network communication issues, and monitor network performance.

PCAP files are used to troubleshoot network communication issues, analyze network traffic, and monitor network performance. 

- They can be used to capture and analyze the data packets of various network protocols, including TCP, UDP, HTTP, and others. 
- PCAP files can be captured from both wired and wireless networks, and can be used to analyze the data packets of both local and remote networks.

PCAP files are commonly used by network administrators, security analysts, and developers to diagnose network problems, identify security threats, and optimize network performance. 

They are an essential tool for monitoring and analyzing network traffic, and can provide valuable insights into the operation of a network.

## Packet Analysis (sniffing, tracing,protocol analysis,traffic analysis)

Packet analysis is the process of capturing and analyzing data packets traveling on a network. It is used to troubleshoot network communication issues, analyze network traffic, and monitor network performance. 

- Packet analysis can be done using network analyzers, such as Wireshark, which capture and display the data packets traveling on the network. Packet analysis can be used to diagnose network problems, identify security threats, and optimize network performance.

## Motivation for packet analysis

- Troubleshoot network communication issues
- Analyze network traffic
- Monitor network performance
- Identify security threats
- Optimize network performance
- Record network activity
- Catch network problems
- Understand network protocols


## TCP (Transmission Control Protocol)

- TCP (Transmission Control Protocol) is a standard that defines how to establish and maintain a network conversation through which application programs can exchange data

- TCP works with the Internet Protocol (IP), which defines how computers send packets of data to each other

- Together, TCP and IP are the basic rules defining the Internet

- TCP is a connection-oriented protocol, which means a connection is established and maintained until the application programs at each end have finished exchanging messages

- It determines how to break application data into packets that networks can deliver, sends packets to and accepts packets from the network layer, manages flow control, and retransmits lost packets

- TCP is used by application protocols such as HTTP, SMTP, Telnet, and FTP

- TCP is a reliable protocol, and it guarantees that the data will be delivered in the same order in which it was sent

- TCP is a connection-oriented protocol, which means that it requires a connection to be established between the two communicating systems before data is exchanged

- TCP is a reliable protocol, which means that it guarantees the delivery of data to the destination system

## Wireshark

As mentioned earlier, Wireshark is a network protocol analyzer that captures and displays the data traveling back and forth on a network. It can be used to capture the TCP three-way handshake between two systems.

- To capture the TCP three-way handshake, start Wireshark and select the network interface that is connected to the network where the communication is taking place

- Once the network interface is selected, Wireshark will start capturing the data packets traveling on the network

- To capture the TCP three-way handshake, filter the captured packets by the IP addresses of the two systems involved in the communication

- The three packets of the TCP three-way handshake will be displayed in the Wireshark capture, showing the SYN, SYN-ACK, and ACK packets

- The captured packets can be analyzed to see the details of the TCP three-way handshake, including the sequence numbers, window sizes, and other connection parameters

Wireshark can be used to:

- troubleshoot network communication issues by capturing and analyzing the data packets traveling on the network
- analyze network traffic by capturing and displaying the data packets traveling on the network
- identify security threats by capturing and analyzing the data packets traveling on the network
- optimize network performance by capturing and analyzing the data packets traveling on the network
- record network activity by capturing and analyzing the data packets traveling on the network
- catch network problems by capturing and analyzing the data packets traveling on the network
- understand network protocols by capturing and analyzing the data packets traveling on the network
- learn about network traffic patterns by capturing and analyzing the data packets traveling on the network


### The wireshark interface

- This has 4 main components: tool bar, packet list pane, packet details pane, packet bytes pane

[img1](/img/img1_wiresharkinterface.png)

## PCAP file location

Pcap file location `git clone https://github.com/mchow01/Bootcamp`

At the terminal start wireshark:

```bash
$ wireshark
```

checking the raw conents in bash:

```bash
cat set1.pcap
```

## Wireshark exercise

Open the pcap file by going to `File` -> `Open` and selecting the `set1.pcap` file in the `Bootcamp` directory

Click on any packet and notice the packet details change (and binary details) in the packet details pane

questions:

1. How many ppackets are there?   8
2. What network protocol is being used? TCP 
3. What is the IP address of the source ? 192.168.1.3
4. What is the IP address of the destination? 192.168.1.8
5. What is the port number the destination is listening on?  7777 and the source is listening on 49859
6. Do you notice the TCP three-way handshake in the packet list pane? - yes you see the SYN, SYN ACK  , ACK pattern

In the packet details pane we see FRame, Ethernet (layer 2), IP (layer 3) and TCP (layer 4) information

Click on IP layer andclick on Source and Destination to see the IP addresses - are visible in the binary pane

You can also notice the SEQ numbers in the TCP layer. These are used to keep track of the packets in the TCP connection and to ensure that they are delivered and assembled in the correct order.

References:

- https://learning.oreilly.com/live-events/packet-analysis-using-wireshark/0636920075846/0636920076709/