# DNS Reconnaisance

## What is DNS Reconnaisance?

DNS reconnaissance is the process of gathering information about a target's DNS infrastructure.

A tool that can be used for this is called `host`.

The `host` command is a simple utility for performing DNS lookups. It can be used to query DNS servers and obtain information about various types of records, such as A, AAAA, MX, NS, and more.

### Example: Using the `host` Command

Here's an example of using the `host` command to perform a DNS lookup for the domain `chester.ac.uk`:

```bash
[cyber@cyberbox ~]$ host -t ns chester.ac.uk

chester.ac.uk name server chandra.chester.ac.uk.
chester.ac.uk name server lister.chester.ac.uk.
chester.ac.uk name server ns4.ja.net.

[cyber@cyberbox ~]$ 

```

---

### Zone Transfer

`Zone transfer` is another technique used in DNS reconnaissance to gather information about a target's DNS records. It involves transferring all the DNS records from a primary DNS server to a secondary DNS server.

If DNS zone transfers are configured incorrectly, an attacker can potentially retrieve sensitive information about the target's DNS records for a domain.

### Example: Using `host` to download DNS records

Here's an example of using the `host` command to download DNS records for the domain `chester.ac.uk`:

```bash
[cyber@cyberbox ~]$ host -l chester.ac.uk chandra.chester.ac.uk
Using domain server:
Name: chandra.chester.ac.uk
Address: 194.80.193.200#53
Aliases: 

Host chester.ac.uk not found: 5(REFUSED)
; Transfer failed.
[cyber@cyberbox ~]$ 

```

From the above example, we can see that the zone transfer failed due to a `REFUSED` response from the DNS server. 

* This is due to the fact that the DNS server is configured to deny zone transfers to unauthorized clients.

Securing zone transfers can be referenced in more detail at the folowing link: <https://www.sans.org/white-papers/868/>

---

**Key Takeaways**

- DNS reconnaissance involves gathering information about a target's DNS infrastructure.
- The `host` command can be used to perform DNS lookups and obtain information about DNS records.
- Zone transfer is a technique used to transfer all DNS records from a primary DNS server to a secondary DNS server.
- Improperly configured zone transfers can expose sensitive information about a target's DNS records.


