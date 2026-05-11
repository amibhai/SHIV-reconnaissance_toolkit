# Reconnaissance Toolkit - Complete Theoretical Analysis

## Overview

Reconnaissance is the foundational phase of any security assessment. It involves systematically gathering information about target systems, networks, and infrastructure without triggering detection. Quality reconnaissance directly determines the success of all subsequent testing phases.

Reconnaissance is divided into two categories:
- **Passive Reconnaissance**: No direct interaction with target (OSINT, DNS lookups)
- **Active Reconnaissance**: Direct interaction with target (port scans, OS detection)

---

## 1. DNS Enumeration

### Theory

DNS (Domain Name System) is a hierarchical distributed database that maps domain names to IP addresses and stores other network information. DNS enumeration systematically extracts this information to map target infrastructure.

### DNS Record Types

| Record | Purpose | Attack Value |
|--------|---------|--------------|
| A | IPv4 address | Direct IP discovery |
| AAAA | IPv6 address | IPv6 infrastructure |
| MX | Mail server | Email infrastructure |
| NS | Name servers | DNS infrastructure |
| TXT | Text records | SPF, DKIM, secrets |
| CNAME | Aliases | Subdomain mapping |
| SOA | Zone authority | Admin contact, serial |
| PTR | Reverse DNS | IP to hostname |
| SRV | Service records | Service discovery |
| AXFR | Zone transfer | Complete DNS dump |

### Zone Transfer Attack (AXFR)

Zone transfers are designed for DNS replication between primary and secondary servers. Misconfigured servers allow anyone to request a complete copy of the DNS zone.

```
Query:  dig AXFR @ns1.target.com target.com
Result: Complete list of all DNS records (hosts, IPs, services)
```

**Why Critical:**
- Reveals entire internal network structure
- Exposes all subdomains
- Discloses internal IP addresses
- Shows infrastructure layout

### Subdomain Enumeration

**Dictionary-Based:**
```
Wordlist: admin, mail, ftp, vpn, dev, staging, api, etc.
Query: admin.target.com → IP exists = valid subdomain
```

**DNS Brute Force:**
- Systematic subdomain guessing
- Pattern-based discovery
- Wildcard detection first

**Certificate Transparency Logs:**
- SSL certificates are publicly logged
- Reveals subdomains from cert history
- Passive, no target interaction

### DNS Cache Snooping

Query DNS server for cached records:
- Reveals which domains have been recently accessed
- Passive reconnaissance technique
- Maps internal browsing patterns

---

## 2. Host Discovery

### Theory

Host discovery determines which IP addresses in a network range are active and responsive. This creates a map of live hosts for further enumeration.

### Techniques

#### ARP Discovery (Layer 2)
- Most reliable on local networks
- Cannot be blocked by firewalls
- MAC address revelation
- Vendor identification from MAC OUI

```
ARP Request: Who has 192.168.1.100?
ARP Reply:   192.168.1.100 is at AA:BB:CC:DD:EE:FF
```

#### ICMP Discovery (Layer 3)

**Echo Request (Type 8):**
```
ping 192.168.1.100
→ ICMP Echo Reply = host alive
→ No reply = host down or filtered
```

**Timestamp Request (Type 13):**
- Some hosts respond to timestamp when not responding to echo
- Reveals hosts blocking standard pings

**Address Mask Request (Type 17):**
- Legacy, rarely used
- Some hosts respond when echo is blocked

#### TCP-Based Discovery

**TCP SYN to common ports:**
```
SYN → port 80  → SYN-ACK = host alive
SYN → port 443 → SYN-ACK = host alive
SYN → port 22  → SYN-ACK = host alive
```

**TCP ACK Scanning:**
```
ACK → any port → RST = host alive (RST means "I'm here but connection invalid")
```

#### UDP Discovery

**UDP to common services:**
```
UDP → port 53  → DNS response = alive
UDP → port 161 → SNMP response = alive
UDP → port 123 → NTP response = alive
```

### Network Range Discovery

**CIDR notation:**
```
192.168.1.0/24  = 254 hosts (192.168.1.1 - 192.168.1.254)
10.0.0.0/8      = 16,777,214 hosts
172.16.0.0/12   = 1,048,574 hosts
```

**Subnet calculation:**
```python
import ipaddress
network = ipaddress.ip_network('192.168.1.0/24')
hosts = list(network.hosts())  # All 254 hosts
```

---

## 3. OS Scanning (OS Fingerprinting)

### Theory

Different operating systems implement TCP/IP stack parameters differently. By analyzing these subtle differences, we can identify the target OS without direct interaction with services.

### Active Fingerprinting Techniques

#### TCP/IP Stack Analysis

**1. Initial TTL Values:**
```
Windows:    TTL = 128
Linux:      TTL = 64
FreeBSD:    TTL = 64
Cisco IOS:  TTL = 255
Solaris:    TTL = 255
```

**2. TCP Window Size:**
```
Windows XP:     65535
Windows 7/10:   8192
Linux 2.6+:     5840
macOS:          65535
FreeBSD:        65535
```

**3. TCP Options:**
- Supported options vary by OS
- Option ordering is OS-specific
- Maximum Segment Size (MSS) values
- SACK (Selective ACK) support
- Timestamps support and values
- Window scaling factors

**4. SYN Packet Analysis:**
```python
# Linux sends:
TCP Options: [MSS 1460, SACK, TS, NOP, WS=7]

# Windows sends:
TCP Options: [MSS 1460, NOP, WS=8, SACK]

# macOS sends:
TCP Options: [MSS 1460, NOP, WS=6, SACK, TS]
```

#### ICMP-Based Fingerprinting

**Response to invalid packets:**
- Error message contents differ by OS
- ICMP error payload size varies
- IP header in error varies

**ICMP echo request features:**
- Response size differences
- DF bit handling
- IP ID incrementing patterns

#### TCP Sequence Number Analysis

**Sequence number generation:**
```
Linux:    Time-based with randomization
Windows:  Random
FreeBSD:  Random with slight patterns
Old Unix: Predictable (vulnerable to spoofing)
```

### Passive Fingerprinting

**Banner Grabbing:**
```
SSH: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
FTP: 220 Microsoft FTP Service
HTTP: Server: Apache/2.4.41 (Ubuntu)
```

**Network Traffic Analysis:**
- Analyze traffic from target without sending probes
- TTL, window size, option patterns
- Completely stealthy

---

## 4. Ping Sweep

### Theory

Ping sweep rapidly identifies all live hosts in a network range by sending ICMP echo requests to each IP. It's the quickest method for initial host discovery.

### Implementation Strategies

#### Sequential Sweep
```
192.168.1.1 → ICMP Echo Request → Wait → Record
192.168.1.2 → ICMP Echo Request → Wait → Record
...
192.168.1.254
```

#### Parallel Sweep (Threaded)
```
Thread 1: 192.168.1.1-63
Thread 2: 192.168.1.64-127
Thread 3: 192.168.1.128-191
Thread 4: 192.168.1.192-254
```

**Performance Comparison:**
- Sequential (0.5s timeout): 127 seconds for /24
- Parallel (10 threads, 0.5s timeout): 13 seconds for /24
- Parallel (50 threads, 0.5s timeout): 3 seconds for /24

#### Randomized Sweep

Randomize target order to evade IDS/SIEM detection:
```python
import random
hosts = list(network.hosts())
random.shuffle(hosts)
for host in hosts:
    ping(host)
```

### ICMP Packet Structure

```
Type: 8 (Echo Request)
Code: 0
Checksum: calculated
Identifier: process ID
Sequence: incrementing counter
Data: padding (usually "abcdefghijklmnop...")
```

### Timeout Considerations

```
0.1s: Fast, misses slow hosts
0.5s: Standard, catches most hosts  
1.0s: Thorough, catches all active hosts
2.0s: Very thorough, detects filtered hosts
```

---

## 5. Port Scanning

### Theory

Port scanning identifies open TCP/UDP ports on target hosts, revealing available services. Each open port is a potential attack vector.

### TCP Scan Types

#### SYN Scan (Half-Open) - Most Common
```
Attacker → SYN     → Target
Attacker ← SYN-ACK ← Target (OPEN)
Attacker → RST     → Target (don't complete handshake)

Advantages:
- Fast
- Stealthy (no full connection logged)
- Works against any TCP service
```

#### TCP Connect Scan (Full Open)
```
Attacker → SYN     → Target
Attacker ← SYN-ACK ← Target
Attacker → ACK     → Target (full handshake)
→ Connection logged by target

Advantages:
- No root required
- Most reliable
Disadvantages:
- Fully logged
- Slower
```

#### FIN Scan (Stealth)
```
Attacker → FIN → Target
No response = OPEN (Linux/Unix)
RST         = CLOSED
ICMP error  = FILTERED

Note: Windows always sends RST regardless
```

#### NULL Scan
```
Attacker → (no flags) → Target
No response = OPEN
RST         = CLOSED
```

#### XMAS Scan (FIN+PSH+URG)
```
Attacker → FIN+PSH+URG → Target
No response = OPEN
RST         = CLOSED
```

#### ACK Scan (Firewall Detection)
```
Attacker → ACK → Target
RST (unfiltered) = No firewall
No response      = Firewall filtering
```

### UDP Scanning

```
Attacker → UDP packet → Target
No response         = OPEN|FILTERED (UDP is stateless)
ICMP Port Unreach   = CLOSED
UDP response        = OPEN
```

**Challenge:** No response could mean open OR filtered → false positives

**Solution:** Service-specific probes:
- DNS: Send DNS query to port 53
- SNMP: Send SNMP get to port 161

### Service Version Detection

Banner grabbing after port confirmed open:
```python
socket.connect((host, port))
banner = socket.recv(1024)
# Analyze banner for service/version
```

### Port Categories

```
Well-Known Ports:  0-1023    (requires root to bind)
Registered Ports:  1024-49151 (IANA registered services)
Dynamic Ports:     49152-65535 (ephemeral/random)
```

### Common Ports Reference

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Clear-text, credential attacks |
| 22 | SSH | Credential attacks |
| 23 | Telnet | Clear-text, legacy |
| 25 | SMTP | Mail relay, spam |
| 53 | DNS | Zone transfers, amplification |
| 80 | HTTP | Web attacks |
| 110 | POP3 | Email credential attacks |
| 135 | RPC | Windows exploitation |
| 139 | NetBIOS | Windows file sharing |
| 143 | IMAP | Email credential attacks |
| 443 | HTTPS | Web attacks (SSL) |
| 445 | SMB | EternalBlue, ransomware |
| 1433 | MSSQL | Database attacks |
| 1521 | Oracle | Database attacks |
| 3306 | MySQL | Database attacks |
| 3389 | RDP | Remote desktop attacks |
| 5432 | PostgreSQL | Database attacks |
| 5900 | VNC | Remote desktop |
| 6379 | Redis | Unauthenticated access |
| 8080 | HTTP Alt | Web attacks |
| 8443 | HTTPS Alt | Web attacks |
| 27017 | MongoDB | Unauthenticated access |

---

## 6. Vulnerability Scanning

### Theory

Vulnerability scanning identifies security weaknesses in discovered services. It combines version detection with CVE databases to flag known vulnerabilities.

### Scanning Methodology

#### Phase 1: Service Version Detection
```
Port 22 → SSH → OpenSSH 7.4
Port 80 → HTTP → Apache 2.2.31
Port 443 → HTTPS → Apache 2.2.31
```

#### Phase 2: CVE Lookup
```
OpenSSH 7.4 → CVE-2018-15473 (User enumeration)
Apache 2.2.31 → CVE-2017-7679 (mod_mime buffer overread)
             → CVE-2017-9788 (mod_auth_digest)
```

#### Phase 3: Risk Assessment
```
CVSS Score: 0.0-3.9 (Low)
           4.0-6.9 (Medium)
           7.0-8.9 (High)
           9.0-10.0 (Critical)
```

### Vulnerability Categories

#### Network-Level
- Weak cipher suites (SSLv2, SSLv3, RC4)
- Open services unnecessarily exposed
- Default credentials
- Unencrypted protocols (Telnet, FTP)

#### Service-Level
- Outdated software versions
- Known CVEs
- Misconfiguration
- Default settings

#### Web Application
- SQL injection (SQLi)
- Cross-site scripting (XSS)
- Command injection
- Directory traversal
- File upload vulnerabilities
- Insecure direct object references (IDOR)

### CVSS v3 Scoring System

```
Base Score = f(Exploitability, ImpactScore)

Exploitability Metrics:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)

Impact Metrics:
- Confidentiality (None/Low/High)
- Integrity (None/Low/High)
- Availability (None/Low/High)
```

### Common Vulnerability Checks

**SSL/TLS:**
```python
# Check for weak protocols
SSLv2:   Critical (deprecated 1996)
SSLv3:   Critical (POODLE attack)
TLSv1.0: High (deprecated)
TLSv1.1: Medium (deprecated)
TLSv1.2: OK (minimum standard)
TLSv1.3: Best (latest)
```

**Default Credentials:**
```
Router: admin:admin, admin:password
Cisco:  cisco:cisco, admin:cisco
MySQL:  root: (empty password)
Redis:  (no auth by default)
MongoDB: (no auth by default pre-3.x)
```

**Version-Based Detection:**
```
Apache 2.4.49 → CVE-2021-41773 (Path traversal/RCE)
Log4j 2.0-2.14.1 → CVE-2021-44228 (Log4Shell - Critical 10.0)
OpenSSL < 1.0.2 → CVE-2014-0160 (Heartbleed)
```

---

## Detection & Evasion

### IDS/SIEM Detection Methods

**Rate-Based Detection:**
- Too many packets per second
- Too many connection attempts
- Sequential IP scanning pattern

**Signature-Based:**
- Known scanning tools (nmap signatures)
- Specific packet patterns
- Unusual flag combinations

### Evasion Techniques

**Slow Scanning:**
```python
# Scan one port per minute to evade rate detection
time.sleep(60)  # Between each probe
```

**Fragmentation:**
```
Split probe packet into multiple fragments
Reassembled only at destination
IDS may not reassemble
```

**Decoy Scanning:**
```
Use multiple fake source IPs
Real attacker IP hidden among decoys
-D decoy1,decoy2,ME,decoy3
```

**Randomization:**
```
Random port order (not sequential)
Random timing
Random source ports
```

---

## Wireless Reconnaissance

### Monitor Mode

Required for passive wireless reconnaissance:

```bash
# Enable monitor mode
airmon-ng start wlan0
→ Creates wlan0mon interface

# Capture all wireless traffic
airodump-ng wlan0mon

# Capture specific network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
```

### Wireless Information Gathering

**Beacon Frames:**
- SSID (network name)
- BSSID (AP MAC address)
- Channel
- Encryption type (WEP/WPA/WPA2/WPA3)
- Supported rates
- Vendor information

**Probe Requests:**
- Client devices probing for known networks
- Reveals client device information
- Shows previously connected networks

**Hidden SSID Discovery:**
- Send deauth to force client reconnect
- Capture probe response with SSID

---

## Output & Reporting

### Scan Output Formats

**Text Output:**
```
Host: 192.168.1.100 (OPEN)
Ports: 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS)
OS: Linux 4.15 (Confidence: 85%)
```

**XML Output:**
```xml
<host>
  <address addr="192.168.1.100" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2"/>
    </port>
  </ports>
</host>
```

**JSON Output:**
```json
{
  "host": "192.168.1.100",
  "ports": [
    {"port": 22, "state": "open", "service": "ssh"},
    {"port": 80, "state": "open", "service": "http"}
  ]
}
```

---

This theoretical foundation guides the implementation of sophisticated, realistic reconnaissance tools for authorized security assessments.
