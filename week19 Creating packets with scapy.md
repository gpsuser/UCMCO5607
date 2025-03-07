# Week 19 - Creating Packets with Scapy


Reference: [Scapy packets from scratch](https://null-byte.wonderhowto.com/how-to/create-packets-from-scratch-with-scapy-for-scanning-dosing-0159231/)

Scapy is a powerful Python-based interactive packet manipulation program and library. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. Scapy can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery. It can replace hping, arpspoof, arp-sk, arping, p0f and even some parts of Nmap, tcpdump, and tshark).

## Start VM
Start kali Vm with the following credentials:

```
Username: kali
Password: kali
```

change to superuser:

```bash
sudo su
password: kali
```

Start scapy:

```bash
scapy
```


## Create a packet from the scapy shell

Create a packet with ttl=64

```python
x = IP(ttl=64)
```

set the source IP address to `192.168.1.101`

```python
x.src = "192.168.1.101"
```

chek to see the packet

```python
x 
```
or

```python
x.show()
```

to get:

```bash
>>> x = IP(ttl=64)
>>> x
<IP  ttl=64 |>
>>> x.src = "192.168.1.101"
>>> x
<IP  ttl=64 src=192.168.1.101 |>
>>> x.show()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = hopopt
  chksum    = None
  src       = 192.168.1.101
  dst       = 127.0.0.1
  \options   \

>>> 
```

Notice that `ttl` refers to the number of hops the packet can make before it is discarded - this is not a `time limit` but a `hop limit`.

Next set the destination IP address to `192.168.1.122`

```python
x.dst = "192.168.1.122"
```

check the packet again

```python
>>> x.dst = "192.168.1.122"

>>> x
<IP  ttl=64 src=192.168.1.101 dst=192.168.1.122 |>
>>> 

```

## List Scapy Commands

```python

>>> lsc()
IPID_count            : Identify IP id values classes in a list of packets
arp_mitm              : ARP MitM: poison 2 target's ARP cache
arpcachepoison        : Poison targets' ARP cache
arping                : Send ARP who-has requests to determine which hosts are up::
arpleak               : Exploit ARP leak flaws, like NetBSD-SA2017-002.
bind_layers           : Bind 2 layers on some specific fields' values.
bridge_and_sniff      : Forward traffic between interfaces if1 and if2, sniff and return
chexdump              : Build a per byte hexadecimal representation
computeNIGroupAddr    : Compute the NI group Address. Can take a FQDN as input parameter
connect_from_ip       : Open a TCP socket to a host:port while spoofing another IP.
corrupt_bits          : Flip a given percentage (at least one bit) or number of bits
corrupt_bytes         : Corrupt a given percentage (at least one byte) or number of bytes
dclocator             : Perform a DC Locator as per [MS-ADTS] sect 6.3.6 or RFC4120.
defrag                : defrag(plist) -> ([not fragmented], [defragmented],
defragment            : defragment(plist) -> plist defragmented as much as possible 
dhcp_request          : Send a DHCP discover request and return the answer.
dns_resolve           : Perform a simple DNS resolution using conf.nameservers with caching
dnssd                 : Performs a DNS-SD (RFC6763) request
dyndns_add            : Send a DNS add message to a nameserver for "name" to have a new "rdata"
dyndns_del            : Send a DNS delete message to a nameserver for "name"
etherleak             : Exploit Etherleak flaw
explore               : Function used to discover the Scapy layers and protocols.
fletcher16_checkbytes : Calculates the Fletcher-16 checkbytes returned as 2 byte binary-string.
fletcher16_checksum   : Calculates Fletcher-16 checksum of the given buffer.
fragleak              : --
fragleak2             : --
fragment              : Fragment a big IP datagram
fuzz                  : Transform a layer into a fuzzy layer by replacing some default values
getmacbyip            : Returns the destination MAC address used to reach a given IP address.
getmacbyip6           : Returns the MAC address of the next hop used to reach a given IPv6 address.
hexdiff               : Show differences between 2 binary strings, Packets...
hexdump               : Build a tcpdump like hexadecimal view
hexedit               : Run hexedit on a list of packets, then return the edited packets.
hexstr                : Build a fancy tcpdump like hex from bytes.
import_hexcap         : Imports a tcpdump like hexadecimal view
is_promisc            : Try to guess if target is in Promisc mode. The target is provided by its ip.
linehexdump           : Build an equivalent view of hexdump() on a single line
ls                    : List  available layers, or infos on a given layer class or name.
neighsol              : Sends and receive an ICMPv6 Neighbor Solicitation message
overlap_frag          : Build overlapping fragments to bypass NIPS
promiscping           : Send ARP who-has requests to determine which hosts are in promiscuous mode
rderf                 : Read a ERF file and return a packet list
rdpcap                : Read a pcap or pcapng file and return a packet list
report_ports          : portscan a target and output a LaTeX table
restart               : Restarts scapy
rfc                   : Generate an RFC-like representation of a packet def.
send                  : Send packets at layer 3
sendp                 : Send packets at layer 2
sendpfast             : Send packets at layer 2 using tcpreplay for performance
smbclient             : A simple smbclient CLI
sniff                 : Sniff packets and return a list of packets.
split_layers          : Split 2 layers previously bound.
sr                    : Send and receive packets at layer 3
sr1                   : Send packets at layer 3 and return only the first answer
sr1flood              : Flood and receive packets at layer 3 and return only the first answer
srbt                  : send and receive using a bluetooth socket
srbt1                 : send and receive 1 packet using a bluetooth socket
srflood               : Flood and receive packets at layer 3
srloop                : Send a packet at layer 3 in loop and print the answer each time
srp                   : Send and receive packets at layer 2
srp1                  : Send and receive packets at layer 2 and return only the first answer
srp1flood             : Flood and receive packets at layer 2 and return only the first answer
srpflood              : Flood and receive packets at layer 2
srploop               : Send a packet at layer 2 in loop and print the answer each time
tcpdump               : Run tcpdump or tshark on a list of packets.
tdecode               : Run tshark on a list of packets.
traceroute            : Instant TCP traceroute
traceroute6           : Instant TCP traceroute using IPv6
traceroute_map        : Util function to call traceroute on multiple targets, then
tshark                : Sniff packets and print them calling pkt.summary().
wireshark             : Runs Wireshark on a list of packets.
wrerf                 : Write a list of packets to a ERF file
wrpcap                : Write a list of packets to a pcap file
wrpcapng              : Write a list of packets to a pcapng file
>>> 


```

## Send the packet

```python
send(x)
```

output:

```bash
.
Sent 1 packets.
>>> 
```

## Create malicious packet and send to a target

We consider the `land` attack which sends a packet to a target with the source IP address set to the target IP address and the destination IP address set to the target IP address (as well as the same source and destination ports).

This causes the target to send a packet to itself and can cause a denial of service attack.

* send packet 2000 times (count=2000)

Define the source and destination ports as follows: 

* sport=135 (defines the source port)
* dport=135 (defines the destination port)

Scapy can implement all these attributes in a single line of code:

```python
send(IP(src="192.168.1.122", dst=""192.168.1.122"/TCP(sport=135, dport=135), count=2000)
```

---