# Legacy Pentest PDF Analysis

Analysis of two PDF deliverables from the November 2025 internal vulnerability
assessment engagement.

Source files:
- executive_summary.pdf (7 pages, 490 KB)
- vulnerability_report.pdf (100 pages, 779 KB)

Analysis date: 2026-02-23


## 1. Scanning Platform / Product

Vendor: Vonahi Security (https://vpentest.io)
Product: vPenTest -- Vonahi's automated internal/external network penetration
testing platform

The underlying vulnerability scanner is OpenVAS (Greenbone). Evidence:
- The User-Agent string in active checks reads:
  "Mozilla/5.0 [en] (X11, U; OpenVAS-VT 23.20.1)"
- All NVT (Network Vulnerability Test) OIDs follow the Greenbone OID scheme
  (1.3.6.1.4.1.25623.x.x.x.x)
- Vulnerability descriptions, CVSS scores, and CERT-Bund references are in
  standard OpenVAS/Greenbone format
- The detailed results XML export (33 MB) follows OpenVAS report schema

The discovery phase uses Nmap:
- Nmap 7.95 was used for host discovery and port scanning
- Scanner host IP: 192.168.101.99 (ens160 interface on a Linux Docker-based VM)
- A Metasploit Framework installation (.msf4 directory) was also present on the
  scanner, suggesting the platform has exploitation capabilities, though no
  exploitation was performed in this assessment

Primary point of contact: Alton Johnson, Principal Security Consultant


## 2. Scan Methodology

### Phases

The assessment followed a two-phase automated approach:

PHASE 1 -- Discovery (host enumeration + port scanning):
- Ping sweep / ARP discovery across target CIDRs
- Nmap TCP SYN + UDP scan against a curated list of ~500 TCP ports and 6 UDP
  ports (not a full 65535 scan)
- Nmap flags: -Pn -T3 -n -sSU (SYN+UDP, timing template 3 "normal", no DNS
  resolution, treat all hosts as up)
- Results: 768 IP addresses scanned, 346 hosts discovered alive
- DNS reverse lookups performed separately (alive_nslookup.txt)
- Scan duration: approximately 214 seconds (3.5 minutes)

PHASE 2 -- Vulnerability Assessment:
- OpenVAS vulnerability scan against all discovered alive hosts
- Authenticated scanning via SMB login (Windows hosts) -- evidenced by
  "Windows SMB Login" detections for 7-Zip, Adobe, .NET Core, BIOS info, etc.
- Unauthenticated network-based checks for SSH, TLS, HTTP, and service-specific
  vulnerabilities
- Active exploitation checks included (e.g., Apache Struts S2-045 RCE was
  actively tested with ipconfig execution)

### Tools Used

- Nmap 7.95 (host discovery and port scanning)
- OpenVAS / Greenbone VT feed 23.20.1 (vulnerability scanning)
- Metasploit Framework (present but exploitation was not part of scope)
- The entire platform runs from a Linux VM (Docker-based, IP 192.168.101.99)


## 3. Scan Scope

### Target Ranges (from targets.txt)

- 192.168.100.0/23 (covers 192.168.100.0-192.168.101.255 = 512 addresses)
- 192.168.199.0/24 (256 addresses)

Total addressable IPs: 768

### Discovered Hosts

- 346 hosts responded as "up" (from Nmap summary)
- 104 hosts appear in the alive.txt file (hosts with actual open ports)
- Approximately 70+ hosts had DNS names resolved in infowerks.com domain

### No Exclusions Documented

There are no documented exclusions in either report or the evidence files.

### Port Scanning Scope

NOT a full 65535 port scan. The Nmap command targeted approximately 500
specific TCP ports (enterprise-focused selection) plus 6 UDP ports:
- TCP: Comprehensive enterprise port list including common services (22, 80,
  443, 445, 3389, etc.), database ports (1433, 3306, 5432), management ports
  (135, 161, 5985, 5986, 5989), and many application-specific ports up to 65535
- UDP: 88 (Kerberos), 161 (SNMP), 389 (LDAP), 500 (IKE), 623 (IPMI),
  5351 (NAT-PMP)


## 4. Authentication

MIXED -- both authenticated and unauthenticated scanning:

Authenticated (Windows hosts via SMB):
- The "Authenticated Scan / LSC Info Consolidation (Windows SMB Login)"
  informational finding confirms SMB-based authenticated scanning was performed
- Software detection via SMB login: 7-Zip, Adobe Flash, Adobe Acrobat,
  AnyDesk, .NET Core, Cygwin, BIOS info were all detected via "Windows SMB
  Login" registry enumeration
- This enabled version-level vulnerability detection for installed software
  that is not exposed via network services

Unauthenticated (network-based):
- SSH protocol/cipher detection
- TLS cipher suite enumeration
- HTTP service fingerprinting and vulnerability checks
- CUPS service detection
- Dell iDRAC/DRAC default credential testing
- Apache Struts active RCE check
- AFP service detection

No evidence of SSH-based authenticated scanning for Linux hosts.


## 5. Risk Rating Methodology

### Overall Severity Ranking

The executive summary states an overall assessment severity ranking that
requires "Immediate remediation or mitigation." The exact wording:

  "Immediate remediation or mitigation is required. Exploitation of identified
  vulnerabilities require minimal effort from an attacker and pose a significant
  threat. A successful attack could result in unauthorized access to systems
  and/or valuable data."

### CVSS Scoring

Vulnerabilities are scored using both CVSS v2 and CVSS v3 base scores, sourced
directly from the OpenVAS NVT feed. Examples:
- CVSS3 9.8: Apache Struts S2-045, Adobe Flash RCE, Apache Tomcat CORS bypass
- CVSS3 7.5: D(HE)ater SSH/TLS, SSH-1 Protocol, .NET Core DoS vulns
- CVSS3 4.3-6.1: Medium severity (XSS, open redirect, info disclosure)
- CVSS3 3.3-3.7: Low severity (DoS with no known fix, info disclosure race)

### Severity Tiers

Findings are categorized into five tiers:
- Critical
- High
- Medium
- Low
- Informational


## 6. Finding Counts by Severity

### Current Assessment (November 15, 2025)

Total vulnerability findings: 142

- Critical: 16
- High: 71
- Medium: 32
- Low: 3
- Informational: 20

### Breakdown by Vulnerability Category

CRITICAL (16 findings):
- 7-Zip: Multiple Vulnerabilities, RCE (2)
- Adobe Flash Player: EOL, 3x Security Updates (4)
- Apache Struts: S2-045 RCE -- ACTIVELY EXPLOITABLE, confirmed ipconfig
  execution (1)
- Apache Tomcat: CORS bypass, EOL, Multiple Vulns Feb 2020, RCE Mar 2025,
  Rewrite Rule Bypass Apr 2025 (5)
- CUPS: Multiple Vulnerabilities Sep/Oct 2024 (1)
- (Remaining 3 from page count alignment)

HIGH (71 findings):
- .NET Core / ASP.NET: ~35 findings (DoS, RCE, Privilege Escalation,
  Information Disclosure, multiple KB patches missing)
- 7-Zip: Mark-of-the-Web bypass, Multiple Vulns Jul 2025, Qcow DoS,
  RAR DoS, UDF code execution, Zstandard underflow, Auth bypass (~7)
- Adobe Flash Player: 4x Security Updates (4)
- Apache Tomcat: ~20 findings (DoS, RCE, Request Smuggling, Session Fixation,
  Privilege Escalation, Info Disclosure across many versions)
- CUPS: Buffer Overflow (1)
- Dell DRAC/iDRAC: Default Credentials -- root/calvin on port 443 (1)
- SSH-1: Deprecated Protocol Detection (1)
- D(HE)ater SSH: DHE KEX DoS (1)
- D(HE)ater TLS: DHE cipher DoS (1)

MEDIUM (32 findings):
- Apache Tomcat: Auth bypass, CGI bypass, HTTP/2, Request Smuggling, Info
  Disclosure, JNDI, DoS, Open Redirect, XSS (~14)
- .NET Core: DoS, Info Disclosure, Spoofing (~8)
- CUPS: DoS, File Permission (2)
- DCE/RPC and MSRPC Enumeration (1)
- Dell OpenManage: Directory Traversal (1)
- AFP Cleartext Login (1)
- Backup File Scanner (1)
- Cleartext HTTP Transmission (1)
- Adobe Flash Player Security Update (1)

LOW (3 findings):
- 7-Zip: Arbitrary File Write Oct 2025, Multiple Vulns Apr 2025 (2)
- Apache Tomcat: Info Disclosure Sep 2022 (1)

INFORMATIONAL (20 findings):
- Detection/inventory findings: 7-Zip, Adobe Flash, Adobe Products, AnyDesk,
  Apache HTTP, Apache Tomcat, CUPS, Dell DRAC/iDRAC, Dell OMSA
- Service enumeration: HTTP methods, DCE/RPC, AFP, ASP.NET Core/.NET Core SDK
- Scan artifacts: Anti-Scanner Defenses, Authenticated Scan Info, BIOS/Hardware
  Info, favicon fingerprinting, Cortana check, Cygwin detection, Windows binary
  compatibility


## 7. Scan Configuration / Profile Names

- Project name: "Monthly Internal network scan"
- Engagement type: "Internal Vulnerability Assessment"
- Assessment component: "Internal Vulnerability Assessment"
- The Nmap scan used specific command-line flags (not a named profile):
  -Pn -T3 -n -sSU with a curated port list
- OpenVAS scan profile name: Not explicitly stated in the PDFs, but the
  authenticated SMB-based scanning plus active checks (like Struts S2-045)
  suggests a comprehensive scan policy rather than a basic/quick scan
- OpenVAS VT version: 23.20.1


## 8. Dates and Timeline

- Assessment date: Saturday, November 15, 2025
- Assessment start time: 12:06 AM PT (per executive summary)
- Nmap discovery scan: Initiated at 08:06:53 UTC (12:06 AM PT),
  completed at 08:10:26 UTC (3.5 minutes)
- Report generation: November 15, 2025
- This is part of an ongoing monthly engagement

### Historical Scan Dates (from trend chart)

The comparison charts show this is a recurring monthly engagement with data from:
- June 21, 2025 -- 2,400+ total findings
- July 19, 2025 -- findings data present
- October 9, 2025 -- findings data present
- November 13, 2025 -- appears to be a separate scan 2 days prior
- November 15, 2025 -- current assessment (142 total findings)

NOTE: The dramatic drop from ~2,400 findings in June to 142 in November suggests
either significant remediation, a scope change, or a change in scan configuration
(possibly removing informational/detection-only findings from the count).


## 9. Remediation Priority Guidance

### Executive Summary Remediation Roadmap

The executive summary's "Remediation Roadmap" section contains only "N/A" for
both the Issue and Remediation Strategy columns. This appears to be an automated
template that was not populated with custom rollup guidance.

The "Engagement Results Summary" section similarly shows "N/A" for both Category
and Summary under "Internal Vulnerability Assessment."

### De Facto Priority Based on Report Content

Based on the vulnerability findings, the implicit priority order is:

IMMEDIATE / P1 -- Active Exploitation Risk:
1. Apache Struts S2-045 RCE on 192.168.101.221 port 443 (CVE-2017-5638)
   -- CONFIRMED CODE EXECUTION (ipconfig ran successfully). This is a CISA
   Known Exploited Vulnerability (KEV). The Tomcat/Struts instance at
   ilas1as09.infowerks.com is trivially exploitable from the network.
2. Dell iDRAC Default Credentials (root/calvin) on 192.168.101.208 port 443
   -- Full hardware management access to ilas2db07 (database server BMC).

HIGH / P2 -- Critical Software Updates:
3. Apache Tomcat 9.0.8 on 192.168.101.69 (ilas1as14) -- severely outdated,
   affected by 20+ vulnerabilities including multiple RCEs. Ports 1311, 9443.
4. 7-Zip 9.20 on 192.168.101.88 (ilas1sql04) -- version from 2010, affected
   by multiple critical RCEs and overflow vulnerabilities.
5. Adobe Flash Player EOL -- still installed on 8 hosts. Should be removed
   entirely (EOL since December 2020).
6. CUPS 2.1 on 192.168.101.200 -- multiple critical vulnerabilities including
   the Sep/Oct 2024 remote code execution chain.
7. .NET Core / ASP.NET runtime and SDK updates across 10+ Windows hosts --
   versions as old as 2.1.6 still deployed.

MEDIUM / P3 -- Cryptographic and Protocol Fixes:
8. D(HE)ater on TLS -- 38+ hosts affected across RDP (3389), HTTPS (443),
   PostgreSQL (5432), SMTP (25), and other TLS services.
9. D(HE)ater on SSH -- 35+ hosts affected on port 22, plus 2 hosts on
   alternate SSH port 1022.
10. Deprecated SSH-1 Protocol -- 3 hosts still accepting SSH-1
    (192.168.100.39, 192.168.101.114, 192.168.101.115).

LOW / P4 -- Hardening:
11. Cleartext HTTP credential transmission
12. AFP cleartext authentication
13. DCE/RPC enumeration exposure
14. HTTP backup file exposure


## 10. Notable Observations

### Authenticated vs Unauthenticated Gap

The scan performed authenticated checks on Windows hosts via SMB but did NOT
perform authenticated scanning on Linux hosts. This means Linux hosts were only
assessed via network-exposed services. Vulnerabilities in locally-installed
software on Linux hosts would not have been detected.

### Scanner Blocking

The "Anti-Scanner Defenses (HTTP)" finding shows that at least 10 hosts in the
192.168.199.0/24 subnet are actively blocking the OpenVAS scanner's User-Agent.
This means vulnerability assessment results for those hosts may be incomplete.

### Pentest Findings vs Vulnerability Findings

The pentest_findings.csv file in the Evidence directory is EMPTY (header only,
no data rows). This confirms the executive summary statement that no
penetration testing / exploitation was performed -- only vulnerability
identification. The Apache Struts S2-045 active check is an exception built
into the OpenVAS NVT, not manual exploitation.

### Scope Coverage

The 192.168.100.0/23 range and 192.168.199.0/24 range together cover the
Infowerks production network. Hostnames suggest:
- Database servers (ilas*db*, ilas*sql*, iSQL1)
- Application servers (ilas*as*)
- Workstations (ilas*wks*, iwnv-w-wks-*)
- Domain controllers (ilas1dc01, ilas1dc03, icage0dc02)
- File servers (ilas*fs*)
- Infrastructure (ilas*drn*, ilas*smtp*, ilas*ftp*, ilas*bu*)
- Storage (ilas*stor*, ilas*nas*)
- Imaging (ILAS*IMG*)

### Software Inventory (from Informational Findings)

Detected across the environment via authenticated SMB scanning:
- 7-Zip: Version 9.20 (2010 vintage) deployed on 40+ Windows hosts
- Adobe Flash Player: Versions 11.8 through 32.0.0.330 on 8 hosts
- Adobe Acrobat 64-bit: Version 25.001.20844 on 10 hosts
- AnyDesk Desktop: Version 9.0.9 on 1 host (ILAS1WKS09)
- Apache Tomcat: Versions 8.5.71 and 9.0.8
- .NET Core runtimes: Versions ranging from 2.1.6 to 8.0.3
- Dell OpenManage Server Administrator: Version 8.2.0
- Cygwin: Detected on multiple hosts
