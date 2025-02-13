# Scapy workshop

We start off with a very basic introduction to Scapy and then move on to a more formal interactive tutorial on the Scapy website.

## Introductory tutorial - Scapy

This initial tutorial uses the `sniff` function to capture packets on a network.

### Step 1: Install Scapy

* Open your VM 
* Create a `week15` folder in your shared folder and `cd` into the directory

Next, create and save a python file called `simple_sniff.py` and add the following code:

```bash
[cyber@cyberbox sf_forensics]$ cd week15
[cyber@cyberbox week15]$ touch simple_sniff.py
[cyber@cyberbox week15]$ nano simple_sniff.py 
```

The code is as follows:

```python
from scapy.all import *

data = sniff(count = 12)
data.nsummary()
```

Next, run the script as `su` (super usaer/root) using the following command:

```bash
[cyber@cyberbox week15]$ su
Password: 
[root@cyberbox week15]# python3 simple_sniff.py 
```

This starts the packet sniffing process. You can stop the process by pressing `Ctrl + C`

Then open firefox and visit a website. You will see the packets being captured in the terminal.

```bash
0000 Ether / IP / UDP / DNS Qry "b'detectportal.firefox.com.'" 
0001 Ether / IP / UDP / DNS Qry "b'detectportal.firefox.com.'" 
0002 Ether / IP / UDP / DNS Ans "b'detectportal.prod.mozaws.net.'" 
0003 Ether / IP / UDP / DNS Ans "b'detectportal.prod.mozaws.net.'" 
0004 Ether / IP / UDP / DNS Qry "b'zerohedge.com.'" 
0005 Ether / IP / UDP / DNS Qry "b'zerohedge.com.'" 
0006 Ether / IP / UDP / DNS Ans 
0007 Ether / IP / UDP / DNS Ans "35.196.136.19" 
0008 Ether / IP / TCP 10.0.2.15:38622 > 35.196.136.19:https S
0009 Ether / IP / TCP 35.196.136.19:https > 10.0.2.15:38622 SA / Padding
0010 Ether / IP / TCP 10.0.2.15:38622 > 35.196.136.19:https A
0011 Ether / IP / TCP 10.0.2.15:38622 > 35.196.136.19:https PA / Raw
```

Notice that it sniffs the first 12 packets. You can change the count to sniff more packets.


Next - we head over to the scapy website and complete the interactive tutorial: <https://scapy.readthedocs.io/en/latest/usage.html>

## Conclusion

Scapy is a powerful tool for network analysis and penetration testing. By understanding how to use it effectively, you can gain valuable insights into network traffic and security vulnerabilities. Remember to always use Scapy responsibly and ethically in your cybersecurity work.

## References

1. Scapy Documentation: https://scapy.readthedocs.io/
2. Engebretson, P. (2013). The Basics of Hacking and Penetration Testing. Syngress.
3. Allen, L. (2012). Advanced Penetration Testing for Highly-Secured Environments. Packt Publishing.
4. NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment
5. OWASP Testing Guide v4.0
```
