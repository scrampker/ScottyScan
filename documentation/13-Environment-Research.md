# Chapter 13 -- Environment Research

This chapter consolidates everything learned about the target scanning environment from the legacy scanner research. This is operational knowledge that helps with ongoing scanning and remediation tracking.

---

## Legacy Scanner Platform

### Platform Identification

- **Vendor:** Vonahi Security (https://vpentest.io)
- **Product:** vPenTest automated penetration testing platform
- **Underlying tools:**
  - OpenVAS / Greenbone VT feed version 23.20.1
  - Nmap 7.95
  - Metasploit Framework (present but not used for exploitation)
- **Scanner host:** 192.168.101.99 (Linux Docker VM, ens160 interface)
- **Engagement:** Monthly internal vulnerability assessment (recurring since June 2025)
- **Last scan:** November 15, 2025 (Saturday)

### Scan Configuration

- **Nmap flags:** `-Pn -T3 -n -sSU` (SYN+UDP, timing normal, no DNS, all hosts treated as up)
- **Port coverage:** 499 specific TCP ports + 6 UDP ports (custom enterprise list, NOT full 65535)
- **OpenVAS config:** Equivalent to "Full and fast" with authenticated Windows SMB + active exploitation checks
- **Authentication:** Windows hosts via SMB login; Linux hosts unauthenticated only
- **Duration:** 3.5 minutes (Nmap) + 9.5 hours (OpenVAS) = ~10 hours total

---

## Target Network

### Subnets

| Subnet | Hosts Discovered | Purpose |
|--------|-----------------|---------|
| 192.168.100.0/24 | 16 hosts | Workstations, some servers |
| 192.168.101.0/24 | 70 hosts | Primary server/infrastructure subnet |
| 192.168.199.0/24 | 16 confirmed (239 phantom from -Pn) | Remote site, heavily firewalled |

- **Total confirmed hosts with open ports:** 104
- **Total hosts in OpenVAS scan:** 102

### Domain: infowerks.com

Active Directory domain with at least 5 domain controllers identified.

### Infrastructure Inventory

#### Domain Controllers (5)

| IP | Hostname | Evidence |
|----|----------|----------|
| 192.168.101.14 | ilas1dc03.infowerks.com | Kerberos + LDAP + DNS + Global Catalog ports |
| 192.168.101.69 | ilas1as14.infowerks.com | AD ports + multiple web apps (unusual combo) |
| 192.168.101.111 | ilas1dc01.infowerks.com | Full AD port signature |
| 192.168.101.112 | icage0dc02.infowerks.com | Full AD port signature |
| 192.168.101.221 | ilas1as09.infowerks.com | AD ports + Apache Struts (CRITICAL VULN) |

#### VMware ESXi Hypervisors (10)

Identified by SSH(22) + HTTP(80) + HTTPS(443) + port 902 + WBEM-HTTPS(5989) + HTTP-ALT(8000):

- 192.168.101.3, .6, .17, .26, .39, .215, .216, .225
- 192.168.199.5, .6

#### Database Servers

- **PostgreSQL** (31 hosts on port 5432) -- heavy PostgreSQL deployment
- **Microsoft SQL Server** (8 hosts on port 1433): ilas1sql02, ilas1sql03, ilas1sql04, iSQL1, and others
- **Pervasive PSQL / Btrieve** (17 hosts on ports 1583/3351) -- Sage/Timberline accounting
- **Firebird/InterBase** (1 host on port 3050)

#### File Servers

- ilas1fs01.infowerks.com (192.168.101.32)
- ilas1fs02.infowerks.com (192.168.101.15)
- ilas2fs05.infowerks.com (192.168.101.253 and .254)

#### NAS/Storage

- ilas1nas01.infowerks.com (192.168.101.8) -- FTP, SSH, HTTP, HTTPS, NFS, AFP, iSCSI, rsync, NDMPS (15 open ports)
- ilas3stor01.infowerks.com (192.168.101.185)

#### Application Servers

- ilas1as04, ilas1as09, ilas1as14, ilas1as23 -- multiple web apps on non-standard ports
- ilas1as09 (192.168.101.221): Apache Struts S2-045 CONFIRMED RCE (CVE-2017-5638)

#### Network/Security Appliances

- **2 Sophos firewalls:** 192.168.101.1 and 192.168.101.250 (ports 3128/squid, 4443, 4444; MAC OUI 7C:5A:1C)
- **2 Dell switches:** 192.168.101.5 and 192.168.101.114/115 (telnet + HTTP + SNMP)

#### Monitoring

- Checkmk agents on 8 hosts (port 6556)
- Dell OpenManage on 11 hosts (port 1311)

#### Hardware

- **Dell physical servers:** 26 (identified by MAC address)
- **Super Micro servers:** 5
- **VMware VMs:** 52

---

## Vulnerability Findings Summary

### Finding Statistics

- **Total findings:** 1000 (including informational)
- **Actionable findings (non-Log):** 431
  - High: 295 (29.5%)
  - Medium: 131 (13.1%)
  - Low: 5 (0.5%)
  - Log/Informational: 569 (56.9%)
- **Unique NVT checks:** 144
- **Unique CVEs:** 154 (spanning 2001--2025)
- **Average CVSS (non-Log):** 7.12

### Critical / Immediate Priority Findings

1. **Apache Struts S2-045 RCE** (CVE-2017-5638) on ilas1as09 (192.168.101.221) port 443
   - CONFIRMED code execution (ipconfig ran successfully)
   - CISA Known Exploited Vulnerability (KEV)
   - Trivially exploitable from the network

2. **Dell iDRAC Default Credentials** (root/calvin) on ilas2db07 (192.168.101.208) port 443
   - Full hardware management access to a database server BMC

3. **Apache Tomcat 9.0.8** on ilas1as14 (192.168.101.69)
   - Severely outdated, 20+ vulnerabilities including multiple RCEs

4. **7-Zip 9.20** on ilas1sql04 (192.168.101.88)
   - Version from 2010, multiple critical RCEs

5. **Adobe Flash Player EOL** on 8 hosts
   - End of life since December 2020, should be uninstalled entirely

### High Volume Findings (ScottyScan Plugin Coverage)

| Finding | Hosts | ScottyScan Plugin |
|---------|-------|-------------------|
| D(HE)ater TLS (CVE-2002-20001) | 43 | DHEater-TLS |
| D(HE)ater SSH | 37 | DHEater-SSH |
| Deprecated SSH-1 Protocol | 3 | SSH1-Deprecated |
| 7-Zip vulnerabilities | 3 | 7Zip-Version |

### Findings NOT Covered by ScottyScan Plugins (Potential Future Plugins)

- .NET Core / ASP.NET vulnerabilities (35+ findings across 12 hosts)
- Apache Tomcat vulnerabilities (20+ unique NVTs across 2 hosts)
- Adobe Flash Player EOL (8 hosts)
- CUPS vulnerabilities (1 host)
- Dell OpenManage directory traversal (2 hosts)
- DCE/RPC enumeration exposure (59 hosts)
- Cleartext HTTP transmission (5 hosts)

---

## Software Inventory Snapshot (November 2025)

Detected via authenticated SMB scanning:

- **7-Zip 9.20** (2010 vintage) -- 40+ Windows hosts
- **Adobe Flash Player 11.8 through 32.0.0.330** -- 8 hosts
- **Adobe Acrobat 64-bit 25.001.20844** -- 10 hosts
- **AnyDesk Desktop 9.0.9** -- 1 host (ILAS1WKS09)
- **Apache Tomcat 8.5.71 and 9.0.8** -- 2 hosts
- **.NET Core runtimes 2.1.6 through 8.0.3** -- 19 hosts
- **Dell OpenManage Server Administrator 8.2.0** -- 11 hosts
- **Cygwin** -- 1 host (ILAS3WKS82)

---

## Historical Trend Data

From the executive summary trend charts:

| Date | Total Findings | Notes |
|------|---------------|-------|
| June 21, 2025 | 2,400+ | First available data point |
| July 19, 2025 | (data present) | -- |
| October 9, 2025 | (data present) | -- |
| November 13, 2025 | (separate scan) | -- |
| November 15, 2025 | 142 (unique) | Current assessment |

The dramatic drop from ~2,400 to 142 may indicate significant remediation, scope changes, or different severity thresholds between scans.

---

## Research Files Reference

All raw analysis files are in `openvas_legacy_research/`:

- `Combined-Deliverables_2025-11-15/` -- Original deliverable package
- `csv_analysis.md` -- Full 26-column CSV analysis (1000 records)
- `nmap_analysis.md` -- Nmap command reconstruction and port analysis
- `pdf_analysis.md` -- Platform identification and methodology
- `Greenbone_CE_Setup_Guide.md` -- Step-by-step GCE replication guide
