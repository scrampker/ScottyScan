# Nmap Scan Analysis -- Legacy Pentest Deliverables (2025-11-15)

Source files:
- port_scans.nmap (human-readable output, 4767 lines)
- port_scans.gnmap (greppable output, 689 lines)

Analysis date: 2026-02-23


## 1. SCAN COMMAND AND OPTIONS

Full command line (extracted from file headers):

    nmap -Pn -T3 -n -sSU \
      -p T:1,7,9,13,19,21,22,23,25,37,42,43,49,53,...[499 TCP ports],U:88,161,389,500,623,5351 \
      -iL /root/pentest/268111/targets.txt \
      --stats-every 10s -vv \
      -oA /root/pentest/268111/discovery/port_scans/port_scans \
      --open

### Flag-by-flag breakdown:

| Flag | Meaning |
|------|---------|
| -Pn | Skip host discovery (treat all targets as up). This is why 346 of 768 IPs report "up" -- they were assumed up, not ping-confirmed. |
| -T3 | Timing template: Normal (default). Not aggressive, not slow. |
| -n | No DNS resolution. |
| -sSU | Combined SYN scan (TCP) + UDP scan. |
| -p T:...,U:... | Explicit port list: 499 TCP ports + 6 UDP ports. |
| -iL /root/pentest/268111/targets.txt | Read target IPs from a file. |
| --stats-every 10s | Print scan progress every 10 seconds. |
| -vv | Very verbose output. |
| -oA ... | Output in all formats (.nmap, .gnmap, .xml). |
| --open | Only show open (or open|filtered) ports in output. |

### What was NOT used:

- NO -sV (service version detection) -- services are identified by port number only, not by banner probing
- NO -O (OS detection)
- NO --script / -sC (NSE script scanning)
- NO -A (aggressive scan, which enables -O, -sV, -sC, --traceroute)
- NO --defeat-rst-ratelimit (mentioned in output notes but not in the command line -- this may have been applied by nmap internally or via a config)

This was a pure port-discovery scan, not a vulnerability assessment scan. No banners, no OS fingerprinting, no scripts.


## 2. SCAN SCOPE AND TIMING

- Nmap version: 7.95
- Scan initiated: Sat Nov 15 08:06:53 2025 UTC
- Scan completed: Sat Nov 15 08:10:26 2025 UTC
- Total scan duration: 213.72 seconds (approximately 3 minutes 34 seconds)
- Total IP addresses targeted: 768
- Hosts reported up: 346
- Hosts reported down: 422

### Subnets scanned (from targets.txt):

| Subnet | Hosts Up | Notes |
|--------|----------|-------|
| 192.168.100.0/24 | 16 | All discovered via ARP (local network). All had open TCP ports. |
| 192.168.101.0/24 | 71 | Mostly ARP-discovered (local network). All had open TCP ports. |
| 192.168.199.0/24 | 256 | Entire /24 reported "up" due to -Pn. Only 17 had open TCP ports. The other 239 showed only open|filtered UDP. |
| TOTAL | 343 unique IPs with port data | 3 hosts (up via -Pn) had no port data lines in gnmap. |

NOTE: The 192.168.199.0/24 subnet is almost certainly a remote/routed network (not directly on the same L2 segment). The -Pn flag forced nmap to scan all 256 addresses regardless of reachability. Of these, 239 hosts reported ONLY "open|filtered" UDP ports with no open TCP ports -- this is a classic false-positive pattern from -Pn scanning through a firewall. The UDP probes received no responses, so nmap cannot distinguish between "open" and "filtered" (hence "open|filtered"). These 239 hosts should be considered uncertain and likely unreachable or heavily firewalled.


## 3. PORT SCANNING APPROACH

### TCP: SYN Scan (-sS)

- Technique: Half-open SYN scan (sends SYN, waits for SYN/ACK or RST, never completes the handshake)
- Evidence: All TCP results show "syn-ack" as the reason for open ports and "reset" for closed ports
- This is the default privileged scan type and the fastest reliable TCP scan method
- Requires root/admin privileges (the scan ran from /root/)

### UDP Scan (-sU)

- Only 6 UDP ports scanned: 88, 161, 389, 500, 623, 5351
- Results are heavily dominated by "open|filtered" (no-response) -- typical for UDP scanning through firewalls
- Only a handful of confirmed open UDP ports (those showing "udp-response" as reason)

### Port Range

- TCP: 499 specific ports (NOT all 65535, NOT a standard nmap default)
- UDP: 6 specific ports
- This is a custom enterprise-focused port list -- NOT nmap's default top-1000 or the --top-ports option

The TCP port list includes a comprehensive set of enterprise services: common services (21-25, 53, 80, 443), Windows infrastructure (88, 135, 139, 389, 445, 636, 3268-3269, 3389, 5985-5986, 47001, 49152), databases (1433, 3050, 3306, 5432-5433), ICS/SCADA (502, 4840, 34962-34964, 44818), web servers/proxies (8080-8090, 8443, 9090, 9443), monitoring (5666, 6556, 9100, 10050-10051), and many more.


## 4. HOST COUNT SUMMARY

| Category | Count |
|----------|-------|
| Total IPs scanned | 768 |
| Hosts reported "up" | 346 |
| Hosts with at least 1 confirmed open TCP port | 104 |
| Hosts with ONLY open|filtered UDP (no confirmed open TCP) | 239 |
| Hosts ARP-discovered (same L2 segment) | 86 |
| Hosts assumed up via -Pn (no ARP, user-set) | 257 |
| Hosts down / not responding | 422 |

### Realistic host count:

If we discount the 239 192.168.199.x hosts that only show open|filtered UDP (likely false positives from -Pn through a firewall), the true number of confirmed live hosts with services is approximately **104**.


## 5. COMPLETE LIST OF UNIQUE OPEN TCP PORTS (61 unique ports)

| Port | Service Name | Count (hosts) | Description |
|------|-------------|---------------|-------------|
| 21 | ftp | 5 | FTP file transfer |
| 22 | ssh | 42 | SSH remote access |
| 23 | telnet | 5 | Telnet (insecure remote access) |
| 25 | smtp | 2 | SMTP mail |
| 53 | domain | 5 | DNS |
| 80 | http | 35 | HTTP web server |
| 81 | hosts2-ns | 1 | Non-standard HTTP (likely web app) |
| 88 | kerberos-sec | 5 | Kerberos authentication (AD domain controllers) |
| 111 | rpcbind | 9 | RPC portmapper (Unix/NFS) |
| 135 | msrpc | 60 | Microsoft RPC endpoint mapper |
| 139 | netbios-ssn | 65 | NetBIOS session service |
| 389 | ldap | 5 | LDAP (AD domain controllers) |
| 443 | https | 22 | HTTPS |
| 445 | microsoft-ds | 65 | SMB / CIFS file sharing |
| 512 | exec | 2 | rexec (insecure Unix r-service) |
| 513 | login | 2 | rlogin (insecure Unix r-service) |
| 548 | afp | 1 | Apple Filing Protocol |
| 623 | oob-ws-http | 2 | IPMI/BMC out-of-band management |
| 631 | ipp | 1 | Internet Printing Protocol (CUPS) |
| 636 | ldapssl | 5 | LDAPS (secure LDAP) |
| 873 | rsync | 1 | rsync file sync |
| 902 | iss-realsecure | 10 | VMware ESXi authentication daemon |
| 990 | ftps | 1 | FTP over TLS |
| 1311 | rxmon | 11 | Dell OpenManage Server Administrator (OMSA) |
| 1433 | ms-sql-s | 8 | Microsoft SQL Server |
| 1583 | simbaexpress | 17 | Pervasive PSQL (Sage/Timberline database) |
| 2049 | nfs | 6 | NFS network file system |
| 2103 | zephyr-clt | 4 | Likely Microsoft MSMQ or custom application |
| 3050 | gds_db | 1 | Firebird/InterBase database |
| 3128 | squid-http | 2 | Squid HTTP proxy |
| 3260 | iscsi | 1 | iSCSI storage target |
| 3268 | globalcatLDAP | 3 | Active Directory Global Catalog |
| 3269 | globalcatLDAPssl | 3 | AD Global Catalog SSL |
| 3351 | btrieve | 17 | Pervasive Btrieve database engine |
| 3389 | ms-wbt-server | 59 | Microsoft RDP (Remote Desktop) |
| 4443 | pharos | 1 | Likely Sophos firewall admin (HTTPS) |
| 4444 | krb524 | 5 | Likely Sophos/pfSense firewall (custom port) |
| 5000 | upnp | 34 | UPnP / likely custom application or web UI |
| 5040 | (unknown) | 20 | Unknown service (Windows, common on modern Win10/11) |
| 5432 | postgresql | 31 | PostgreSQL database |
| 5433 | pyrrho | 2 | Likely PostgreSQL secondary instance |
| 5900 | vnc | 1 | VNC remote desktop |
| 5985 | wsman | 18 | WinRM HTTP (PowerShell remoting) |
| 5989 | wbem-https | 10 | WBEM/CIM (VMware ESXi management) |
| 6000 | X11 | 4 | X Window System (Unix display) |
| 6556 | checkmk-agent | 8 | Checkmk monitoring agent |
| 7080 | empowerid | 2 | Likely WSO2/WebLogic or custom web app |
| 8000 | http-alt | 10 | HTTP alternate (VMware ESXi VAMI) |
| 8080 | http-proxy | 1 | HTTP proxy / alternate web server |
| 8088 | radan-http | 1 | Likely web application |
| 8090 | opsmessaging | 1 | Likely web application or API |
| 8300 | tmi | 4 | Likely VMware VSAN or custom service |
| 8443 | https-alt | 1 | HTTPS alternate |
| 9084 | aurora | 2 | Likely application server |
| 9090 | zeus-admin | 1 | Likely Cockpit web console (Linux) |
| 9443 | tungsten-https | 1 | Likely application server HTTPS |
| 10080 | amanda | 1 | Likely web application (non-standard HTTP) |
| 11000 | irisa | 3 | Likely AD-related high port |
| 30000 | ndmps | 1 | NDMP storage (NAS device) |
| 47001 | winrm | 31 | WinRM HTTPS (Windows Remote Management) |
| 49152 | (unknown) | 32 | Windows RPC dynamic port range |


## 6. UNIQUE OPEN/FILTERED UDP PORTS (6 ports scanned)

| Port | Service Name | Confirmed Open | Open/Filtered | Notes |
|------|-------------|----------------|---------------|-------|
| 88 | kerberos-sec | 3 (udp-response) | 263 (no-response) | AD domain controllers confirmed on .14, .111, .112 |
| 161 | snmp | 6 (udp-response) | 246 (no-response) | SNMP confirmed on switches, ESXi hosts, iDRAC |
| 389 | ldap | 3 (udp-response) | 288 (no-response) | CLDAP on domain controllers |
| 500 | isakmp | 0 | 315 (no-response) | IPsec/IKE -- all unconfirmed |
| 623 | asf-rmcp | 1 (udp-response) | 257 (no-response) | IPMI on .208 confirmed |
| 5351 | nat-pmp | 0 | 258 (no-response) | NAT-PMP -- all unconfirmed |


## 7. SERVICE IDENTIFICATION SUMMARY

Since -sV was not used, all service names are based on nmap's port-to-service database (nmap-services file), NOT on actual banner/probe identification. The actual services could differ from what nmap reports.

### Windows Infrastructure (dominant profile):
- 65 hosts with SMB (445) -- the most common service
- 60 hosts with MSRPC (135)
- 59 hosts with RDP (3389)
- 18 hosts with WinRM/WS-Management (5985)
- 31 hosts with WinRM HTTPS (47001)
- 5 hosts running Active Directory domain controller services (53, 88, 389, 636, 3268, 3269)

### Linux/Unix Infrastructure:
- 42 hosts with SSH (22)
- 9 hosts with RPC portmapper (111)
- 6 hosts with NFS (2049)
- 4 hosts with X11 (6000)

### VMware ESXi Hypervisors:
- 10 hosts showing the ESXi signature: SSH(22) + HTTP(80) + HTTPS(443) + port 902 + WBEM-HTTPS(5989) + HTTP-ALT(8000)
- Located across all 3 subnets: 192.168.101.3, .6, .17, .26, .39, .215, .216, .225 and 192.168.199.5, .6
- Some also show port 8300 (VSAN/vSphere Replication)

### Database Servers:
- 31 hosts with PostgreSQL (5432) -- very heavy PostgreSQL deployment
- 8 hosts with Microsoft SQL Server (1433)
- 17 hosts with Pervasive PSQL / Btrieve (1583, 3351) -- Sage/Timberline accounting software
- 1 host with Firebird/InterBase (3050)

### Network/Security Appliances:
- 2 Sophos firewalls: 192.168.101.1 and 192.168.101.250 (identified by MAC OUI 7C:5A:1C and ports 3128/squid, 4443, 4444)
- 2 Dell switches: 192.168.101.5 and 192.168.101.114/115 (telnet + HTTP + SNMP, Dell MAC)

### Monitoring:
- 8 hosts with Checkmk agent (6556)
- 11 hosts with Dell OpenManage (1311)

### NAS/Storage:
- 192.168.101.200 -- NAS device with FTP, SSH, HTTP, HTTPS, NFS, AFP, iSCSI, rsync, NDMPS (ICP Electronics MAC)


## 8. MAC ADDRESS VENDOR DISTRIBUTION

| Vendor | Count | Implication |
|--------|-------|-------------|
| VMware | 52 | Virtual machines |
| Dell | 26 | Physical servers (ESXi hosts, domain controllers, iDRAC) |
| Super Micro Computer | 5 | Physical servers |
| Sophos | 2 | Firewall appliances |
| ICP Electronics | 1 | NAS/storage device |

NOTE: Only 86 of 343 hosts had MAC addresses (ARP-discovered on same L2). The remaining 257 (nearly all 192.168.199.x) were on a remote subnet and discovered via -Pn with "received user-set".


## 9. NOTABLE FINDINGS

### Security Concerns:

1. **Telnet exposed (5 hosts)**: 192.168.100.39, 192.168.101.5, 192.168.101.114, 192.168.101.115, 192.168.101.122 -- telnet is cleartext and should be disabled
2. **rexec/rlogin exposed (2 hosts)**: 192.168.100.39, 192.168.101.122 -- these are insecure Berkeley r-services (ports 512, 513)
3. **VNC exposed (1 host)**: 192.168.101.208 -- VNC on port 5900, may lack encryption
4. **FTP exposed (5 hosts)**: Including 192.168.101.114/115 (network switches with FTP+telnet+SNMP)
5. **X11 exposed (4 hosts)**: 192.168.100.14, 192.168.101.8, .13, 192.168.199.8 -- X Window on port 6000, typically should not be network-accessible
6. **FTPS on 192.168.199.22**: Port 990 (FTP over TLS), unusual standalone occurrence
7. **Broad RDP exposure**: 59 hosts with port 3389 open -- significant attack surface for D(HE)ater and other RDP vulnerabilities

### Interesting Infrastructure:

8. **Domain controllers identified (5 hosts)**: 192.168.101.14, .69, .111, .112, .221 -- evidenced by Kerberos(88) + LDAP(389) + LDAPS(636) + Global Catalog(3268/3269) + DNS(53)
9. **Heavy Pervasive PSQL deployment (17 hosts)**: Ports 1583 (Simba Express) and 3351 (Btrieve) indicate Sage/Timberline ERP across many workstations/servers
10. **PostgreSQL on 31 hosts**: Unusually high PostgreSQL deployment, likely part of a Checkmk or application stack
11. **192.168.199.0/24 subnet mostly phantom hosts**: 239 of 256 addresses reported only open|filtered UDP due to -Pn forcing scans against likely unreachable hosts. These are false positives for practical purposes.
12. **Interesting high-port hosts**:
    - 192.168.101.69 and .221: Multiple web apps on non-standard ports (7080, 8088, 9084, 9443, 10080) alongside AD domain controller services
    - 192.168.101.200: NAS device with 15 open ports including iSCSI (3260), AFP (548), NFS (2049), NDMPS (30000)
13. **192.168.199.0 and 192.168.199.255 with port 4444**: These network/broadcast addresses having open ports suggests they are actually gateway devices (Sophos pattern matches 192.168.101.1 and .250)


## 10. COMPARISON WITH SCOTTYSCAN APPROACH

### What this nmap scan does that ScottyScan also does:
- TCP port scanning (nmap uses SYN scan; ScottyScan uses async TCP connect)
- Multiple host scanning from a target list

### What this nmap scan does that ScottyScan does NOT do:
- UDP scanning (ScottyScan is TCP-only)
- Combined SYN+UDP in a single pass

### What ScottyScan does that this nmap scan did NOT do:
- Service version detection (ScottyScan does TLS ClientHello and SSH KEX_INIT parsing)
- OS fingerprinting (ScottyScan does TTL-based + CIM/WMI + SSH banner)
- Vulnerability testing (ScottyScan runs plugin-based vuln checks)
- Full port range (ScottyScan scans all 65535 by default; this nmap scan only did 499 TCP + 6 UDP)

### Implications for ScottyScan port list:
The 499-port list from this nmap scan is a good candidate for ScottyScan's "Top enterprise ports" option. It covers significantly more ports than ScottyScan's current "Top 100" option while still being much faster than a full 65535 sweep. Key ports in this list that should be verified against ScottyScan's built-in list: 1583, 3351 (Pervasive PSQL), 6556 (Checkmk), 1311 (Dell OMSA), 8300 (VSAN), 5989 (WBEM), 30000 (NDMPS).


## 11. RAW SCAN STATISTICS

- Nmap version: 7.95
- Scan start: 2025-11-15 08:06:53 UTC
- Scan end: 2025-11-15 08:10:26 UTC
- Duration: 213.72 seconds
- Total targets: 768 IP addresses
- Hosts up: 346
- Hosts down: 422
- TCP ports per host: 499
- UDP ports per host: 6
- Total port probes: ~348,000+ (768 x 505 theoretical maximum, minus early termination for down hosts)
- Run from: /root/pentest/268111/ (Linux pentest system)
- Data files path: /usr/local/bin/../share/nmap
