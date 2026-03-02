# OpenVAS Detailed Results CSV -- Full Analysis

Source file: detailedresults.csv
File size: 2,046,082 bytes
Total records parsed: 1000
Analysis date: 2026-02-23

---

## 1. CSV Schema (Column Headers)

The CSV contains 26 columns:

```
   1. IP
   2. Hostname
   3. Port
   4. Port Protocol
   5. CVSS
   6. Severity
   7. QoD
   8. Solution Type
   9. NVT Name
  10. Summary
  11. Specific Result
  12. NVT OID
  13. CVEs
  14. Task ID
  15. Task Name
  16. Timestamp
  17. Result ID
  18. Impact
  19. Solution
  20. Affected Software/OS
  21. Vulnerability Insight
  22. Vulnerability Detection Method
  23. Product Detection Result
  24. BIDs
  25. CERTs
  26. Other References
```

---

## 2. Severity Distribution

| Severity | Count | Percent |
|----------|------:|--------:|
| High | 295 | 29.5% |
| Medium | 131 | 13.1% |
| Low | 5 | 0.5% |
| Log | 569 | 56.9% |
| **TOTAL** | **1000** | **100%** |

CVSS range: 0.0 -- 10.0
CVSS average: 3.07
CVSS average (excluding 0.0 / Log): 7.12

---

## 3. Unique NVT Names by Severity

Total unique NVT checks: 144

### High (87 unique NVTs)

- .NET Core Denial of Service And Information Disclosure Vulnerabilities - Windows [12 findings]
- .NET Core Denial of Service Vulnerability - Windows [5 findings]
- .NET Core DoS Vulnerability (Feb 2024) - Windows [2 findings]
- .NET Core DoS Vulnerability (May 2020) [1 findings]
- .NET Core Elevation of Privilege Vulnerability (Mar 2025) [7 findings]
- .NET Core Multiple Denial of Service Vulnerabilities (KB5014326) [6 findings]
- .NET Core Multiple Denial of Service Vulnerabilities (KB5036452) [1 findings]
- .NET Core Multiple DoS Vulnerabilities - Windows [1 findings]
- .NET Core Multiple DoS Vulnerabilities-01 (May 2019) [2 findings]
- .NET Core Multiple DoS Vulnerabilities-02 (May 2019) [1 findings]
- .NET Core Multiple Vulnerabilities (KB5033734) [1 findings]
- .NET Core Multiple Vulnerabilities (KB5041081) [2 findings]
- .NET Core Multiple Vulnerabilities (KB5042132) [2 findings]
- .NET Core Multiple Vulnerabilities (KB5045993) [2 findings]
- .NET Core Multiple Vulnerabilities (Oct 2025) [11 findings]
- .NET Core Multiple Vulnerabilities (Sep 2019) [1 findings]
- .NET Core Multiple Vulnerabilities - Windows [2 findings]
- .NET Core OData Denial of Service Vulnerability - Windows [1 findings]
- .NET Core Privilege Escalation Vulnerability (KB5037337) [1 findings]
- .NET Core Privilege Escalation Vulnerability (KB5037338) [2 findings]
- .NET Core RCE Vulnerability (Jan 2025) [9 findings]
- .NET Core RCE Vulnerability (January-1 2025) [9 findings]
- .NET Core RCE Vulnerability (Jun 2025) [7 findings]
- .NET Core Remote Code Execution Vulnerability - Windows [5 findings]
- .NET Core SDK DoS Vulnerability (May 2020) [1 findings]
- .NET Core SDK Multiple DoS Vulnerabilities-01 (May 2019) [2 findings]
- .NET Core SDK Multiple DoS Vulnerabilities-02 (May 2019) [1 findings]
- .NET Core SDK Multiple Vulnerabilities (Sep 2019) [1 findings]
- .NET Core SDK Security Feature Bypass Vulnerability (Sep 2020) [1 findings]
- .NET Core Security Feature Bypass Vulnerability (Sep 2020) [9 findings]
- .NET Core Spoofing Vulnerability (May 2025) [7 findings]
- 7-Zip Mark-of-the-Web Bypass Vulnerability (Jan 2025) - Windows [2 findings]
- 7-Zip Multiple Vulnerabilities (Jul 2025) - Windows [2 findings]
- 7-Zip Multiple Vulnerabilities - Windows [1 findings]
- 7-Zip Qcow Handler Infinite Loop DoS Vulnerability - Windows [1 findings]
- 7-Zip RCE Vulnerability - Windows [1 findings]
- 7-Zip Zstandard Decompression Integer Underflow Vulnerability - Windows [1 findings]
- 7Zip UDF CInArchive::ReadFileItem Code Execution Vulnerability [1 findings]
- 7zip Authentication Bypass Vulnerability - Windows [1 findings]
- 7zip RAR Denial of Service Vulnerability - Windows [1 findings]
- Adobe Flash Player End of Life (EOL) Detection [8 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-19) - Windows [1 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-26) - Windows [1 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-30) - Windows [1 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-46) - Windows [1 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-06) - Windows [4 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-30) - Windows [7 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-58) - Windows [7 findings]
- Apache Struts Security Update (S2-045) - Active Check [2 findings]
- Apache Tomcat CORS Filter Setting Security Bypass Vulnerability [1 findings]
- Apache Tomcat Clustering DoS Vulnerability (May 2022) [2 findings]
- Apache Tomcat DoS Vulnerability (Feb 2023) - Windows [2 findings]
- Apache Tomcat DoS Vulnerability (Jul 2024) - Windows [2 findings]
- Apache Tomcat DoS Vulnerability (Jul 2025) - Windows [2 findings]
- Apache Tomcat DoS Vulnerability (Jun 2019) - Windows [2 findings]
- Apache Tomcat DoS Vulnerability (Jun 2020) - Windows [1 findings]
- Apache Tomcat DoS Vulnerability (Mar 2019) - Windows [1 findings]
- Apache Tomcat DoS Vulnerability (Oct 2021) - Windows [1 findings]
- Apache Tomcat DoS Vulnerability (Sep 2021) - Windows [1 findings]
- Apache Tomcat End of Life (EOL) Detection - Windows [1 findings]
- Apache Tomcat HTTP/2 Protocol DoS Vulnerability (MadeYouReset) - Windows [2 findings]
- Apache Tomcat HTTP/2 Vulnerability (Dec 2020) - Windows [1 findings]
- Apache Tomcat Hostname Verification Security Bypass Vulnerability - Windows [1 findings]
- Apache Tomcat Information Disclosure Vulnerability (Mar 2021) - Windows [1 findings]
- Apache Tomcat Local Privilege Escalation Vulnerability (Jan 2022) - Windows [1 findings]
- Apache Tomcat Multiple DoS Vulnerabilities (Jul 2020) - Windows [1 findings]
- Apache Tomcat Multiple DoS Vulnerabilities (Jul 2025) - Windows [2 findings]
- Apache Tomcat Multiple Vulnerabilities (Feb 2020) - Windows [1 findings]
- Apache Tomcat Multiple Vulnerabilities (Jun 2025) - Windows [2 findings]
- Apache Tomcat Multiple Vulnerabilities (Oct 2023) - Windows [2 findings]
- Apache Tomcat Privilege Escalation Vulnerability (Dec 2019) - Windows [1 findings]
- Apache Tomcat RCE Vulnerability (Apr 2019) - Windows [1 findings]
- Apache Tomcat RCE Vulnerability (Mar 2021) - Windows [1 findings]
- Apache Tomcat RCE Vulnerability (Mar 2025) - Windows [2 findings]
- Apache Tomcat RCE Vulnerability (May 2020) - Windows [1 findings]
- Apache Tomcat Request Mix-up Vulnerability (May 2022) - Windows [2 findings]
- Apache Tomcat Request Smuggling Vulnerability (Nov 2023) - Windows [2 findings]
- Apache Tomcat Request Smuggling Vulnerability (Oct 2022) - Windows [2 findings]
- Apache Tomcat Rewrite Rule Bypass Vulnerability (Apr 2025) - Windows [2 findings]
- Apache Tomcat Session Fixation Vulnerability (Aug 2025) - Windows [2 findings]
- Apache Tomcat Session Fixation Vulnerability (Dec 2019) - Windows [1 findings]
- CUPS < 2.4.7 Buffer Overflow Vulnerability [1 findings]
- CUPS Multiple Vulnerabilities (Sep/Oct 2024) [1 findings]
- Dell DRAC / iDRAC Default Credentials (HTTP) [1 findings]
- Deprecated SSH-1 Protocol Detection [3 findings]
- Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater) [39 findings]
- Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater) [45 findings]

### Medium (32 unique NVTs)

- .NET Core Denial of Service Vulnerability (Jun 2021) [12 findings]
- .NET Core Information Disclosure Vulnerabilities - Windows [5 findings]
- .NET Core Information Disclosure Vulnerability (KB5015424) [6 findings]
- .NET Core Multiple Vulnerabilities (KB5038351) [4 findings]
- .NET Core SDK Spoofing Vulnerability (Feb 2019) [3 findings]
- .NET Core SDK Spoofing Vulnerability (Jul 2019) [1 findings]
- .NET Core Spoofing Vulnerability (Feb 2019) [3 findings]
- .NET Core Spoofing Vulnerability (Jul 2019) [1 findings]
- Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-06) - Windows [1 findings]
- Apache Tomcat Authentication Bypass Vulnerability (Nov 2024) - Windows [2 findings]
- Apache Tomcat CGI Security Constraint Bypass Vulnerability (May 2025) - Windows [2 findings]
- Apache Tomcat HTTP Request Smuggling Vulnerability (Jul 2021) - Windows [1 findings]
- Apache Tomcat HTTP/2 Vulnerability (Oct 2020) - Windows [1 findings]
- Apache Tomcat Information Disclosure Vulnerability (Jan 2021) - Windows [1 findings]
- Apache Tomcat Information Disclosure Vulnerability (Jan 2024) - Windows [1 findings]
- Apache Tomcat Information Disclosure Vulnerability (Mar 2023) - Windows [2 findings]
- Apache Tomcat JNDI Realm Authentication Weakness Vulnerability (Jul 2021) - Windows [1 findings]
- Apache Tomcat Multiple DoS Vulnerabilities (Mar 2024) - Windows [2 findings]
- Apache Tomcat Multiple Vulnerabilities (Dec 2024) - Windows [2 findings]
- Apache Tomcat NIO/NIO2 Connectors Information Disclosure Vulnerability - Windows [1 findings]
- Apache Tomcat Open Redirect Vulnerability (Aug 2023) - Windows [2 findings]
- Apache Tomcat Open Redirect Vulnerability - Windows [1 findings]
- Apache Tomcat XSS Vulnerability (Jun 2022) - Windows [1 findings]
- Apache Tomcat XSS Vulnerability (May 2019) - Windows [1 findings]
- AppleShare IP / Apple Filing Protocol (AFP) Unencrypted Cleartext Login [1 findings]
- Backup File Scanner (HTTP) - Unreliable Detection Reporting [4 findings]
- CUPS < 2.4.13 Multiple Vulnerabilities [1 findings]
- CUPS < 2.4.3 DoS Vulnerability [1 findings]
- CUPS < 2.4.9 File Permission Vulnerability [1 findings]
- Cleartext Transmission of Sensitive Information via HTTP [5 findings]
- DCE/RPC and MSRPC Services Enumeration Reporting [77 findings]
- Dell OpenManage Server Administrator Directory Traversal Vulnerability (Apr 2016) [2 findings]

### Low (3 unique NVTs)

- 7-Zip Arbitrary File Write Vulnerability (Oct 2025) - Windows [2 findings]
- 7-Zip Multiple Vulnerabilities (Apr 2025) - Windows [1 findings]
- Apache Tomcat Information Disclosure Vulnerability (Sep 2022) - Windows [2 findings]

### Log (23 unique NVTs)

- 7zip Detection (Windows SMB Login) [46 findings]
- ASP.NET Core/.NET Core SDK Detection (Windows SMB Login) [45 findings]
- Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login) [8 findings]
- Adobe Products Detection (Windows SMB Login) [10 findings]
- Allowed HTTP Methods Enumeration [89 findings]
- Anti-Scanner Defenses (HTTP) [10 findings]
- AnyDesk Desktop Detection Consolidation [1 findings]
- Apache HTTP Server Detection Consolidation [2 findings]
- Apache Tomcat Detection Consolidation [1 findings]
- Apple / OpenPrinting CUPS Detection (HTTP) [1 findings]
- AppleShare IP / Apple Filing Protocol (AFP) Service Detection [1 findings]
- Authenticated Scan / LSC Info Consolidation (Windows SMB Login) [62 findings]
- BIOS and Hardware Information Detection (Windows SMB Login) [48 findings]
- CPE Inventory [101 findings]
- Check for Windows 10 Cortana Search [26 findings]
- Check open ports [21 findings]
- Compatibility Issues Affecting Signed Microsoft Binaries (2749655) [2 findings]
- Cygwin Detection (Windows SMB Login) [1 findings]
- DCE/RPC and MSRPC Services Enumeration [59 findings]
- DCE/RPC and MSRPC Services Enumeration Reporting [77 findings]
- Dell DRAC / iDRAC Detection Consolidation [1 findings]
- Dell EMC OpenManage Server Administrator (OMSA) Detection (HTTP) [10 findings]
- favicon.ico Based Fingerprinting (HTTP) [6 findings]

---

## 4. Unique Ports

Total unique port/protocol pairs: 43

| Port/Protocol | Findings |
|--------------|----------:|
| 22/tcp | 43 |
| 23/tcp | 1 |
| 25/tcp | 1 |
| 80/tcp | 38 |
| 135/tcp | 119 |
| 443/tcp | 24 |
| 548/tcp | 2 |
| 631/tcp | 7 |
| 1022/tcp | 2 |
| 1311/tcp | 59 |
| 1536/tcp | 1 |
| 1537/tcp | 1 |
| 1538/tcp | 1 |
| 1539/tcp | 1 |
| 1540/tcp | 1 |
| 1541/tcp | 1 |
| 1542/tcp | 1 |
| 1572/tcp | 1 |
| 1587/tcp | 1 |
| 2103/tcp | 3 |
| 2105/tcp | 3 |
| 2107/tcp | 3 |
| 3002/tcp | 1 |
| 3003/tcp | 1 |
| 3033/tcp | 3 |
| 3232/tcp | 1 |
| 3269/tcp | 3 |
| 3389/tcp | 29 |
| 4444/tcp | 2 |
| 5000/tcp | 37 |
| 5432/tcp | 6 |
| 5989/tcp | 5 |
| 7070/tcp | 1 |
| 8084/tcp | 3 |
| 8088/tcp | 2 |
| 8090/tcp | 2 |
| 9084/tcp | 3 |
| 9087/tcp | 3 |
| 9090/tcp | 1 |
| 9443/tcp | 26 |
| 10080/tcp | 2 |
| 20003/tcp | 1 |
| 47001/tcp | 4 |

Numeric port list (sorted): 22, 23, 25, 80, 135, 443, 548, 631, 1022, 1311, 1536, 1537, 1538, 1539, 1540, 1541, 1542, 1572, 1587, 2103, 2105, 2107, 3002, 3003, 3033, 3232, 3269, 3389, 4444, 5000, 5432, 5989, 7070, 8084, 8088, 8090, 9084, 9087, 9090, 9443, 10080, 20003, 47001

---

## 5. Unique IPs Scanned

Total unique IPs: 102

| IP | Hostname | Total Findings | Critical | High | Medium | Low | Log |
|----|----------|---------------:|---------:|-----:|-------:|----:|----:|
| 192.168.100.14 |  | 5 | 0 | 1 | 2 | 0 | 2 |
| 192.168.100.18 | ilas3smtp01.infowerks.com | 7 | 0 | 0 | 2 | 0 | 5 |
| 192.168.100.21 | ilas2ftp01.infowerks.com | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.100.39 | ilas1qa03.infowerks.com | 9 | 0 | 2 | 1 | 0 | 6 |
| 192.168.100.54 | ilas2wks27.infowerks.com | 7 | 0 | 1 | 1 | 0 | 5 |
| 192.168.100.69 | iwnv-w-wks-judd3.infowerks.com | 6 | 0 | 0 | 1 | 0 | 5 |
| 192.168.100.100 | ilas1wagswks01.infowerks.com | 3 | 0 | 0 | 0 | 0 | 3 |
| 192.168.100.159 | ilas3wks81.infowerks.com | 9 | 0 | 1 | 1 | 0 | 7 |
| 192.168.100.160 | ilas3wks82.infowerks.com | 9 | 0 | 1 | 1 | 0 | 7 |
| 192.168.100.164 | ilas1win1002.infowerks.com | 18 | 0 | 2 | 3 | 0 | 13 |
| 192.168.100.165 | ilas1win1003.infowerks.com | 22 | 0 | 6 | 4 | 0 | 12 |
| 192.168.100.170 | ilas3wks87.infowerks.com | 20 | 0 | 9 | 2 | 0 | 9 |
| 192.168.100.171 | ilas3wks88.infowerks.com | 13 | 0 | 3 | 1 | 0 | 9 |
| 192.168.100.184 | ilas3wks95a.infowerks.com | 13 | 0 | 4 | 1 | 0 | 8 |
| 192.168.100.185 | ilas3wks95.infowerks.com | 8 | 0 | 0 | 1 | 0 | 7 |
| 192.168.100.200 | ilas3db05.infowerks.com | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.101.1 | _gateway | 2 | 0 | 1 | 0 | 0 | 1 |
| 192.168.101.3 |  | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.101.5 |  | 4 | 0 | 0 | 2 | 0 | 2 |
| 192.168.101.6 |  | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.101.8 | ilas1nas01.infowerks.com | 5 | 0 | 1 | 2 | 0 | 2 |
| 192.168.101.11 | ilas1bu02.infowerks.com | 5 | 0 | 0 | 1 | 0 | 4 |
| 192.168.101.12 |  | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.101.13 |  | 5 | 0 | 1 | 2 | 0 | 2 |
| 192.168.101.14 | ilas1dc03.infowerks.com | 8 | 0 | 0 | 1 | 0 | 7 |
| 192.168.101.15 | ilas1fs02.infowerks.com | 6 | 0 | 0 | 1 | 0 | 5 |
| 192.168.101.17 | ilas1sw01.infowerks.com | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.101.24 |  | 6 | 0 | 2 | 0 | 0 | 4 |
| 192.168.101.26 | ilas1qa02.infowerks.com | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.101.29 | sf-archive.infowerks.com | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.101.32 | ilas1fs01.infowerks.com | 6 | 0 | 0 | 1 | 0 | 5 |
| 192.168.101.36 | ilas1sql03.infowerks.com | 3 | 0 | 2 | 0 | 0 | 1 |
| 192.168.101.39 |  | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.101.50 |  | 4 | 0 | 2 | 0 | 0 | 2 |
| 192.168.101.51 | ilas1drn01.infowerks.com | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.101.53 | ilas1drn03.infowerks.com | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.101.63 | ilas1img01.infowerks.com | 7 | 0 | 0 | 1 | 0 | 6 |
| 192.168.101.66 | ilas0sql02a.infowerks.com | 7 | 0 | 1 | 1 | 0 | 5 |
| 192.168.101.69 | ilas1as14.infowerks.com | 84 | 0 | 48 | 22 | 2 | 12 |
| 192.168.101.83 | ilas1as23.infowerks.com | 25 | 0 | 12 | 4 | 0 | 9 |
| 192.168.101.84 | ilas3wks03.infowerks.com | 34 | 0 | 12 | 4 | 0 | 18 |
| 192.168.101.85 | ilas3wks04.infowerks.com | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.101.88 | ilas1sql04.infowerks.com | 19 | 0 | 9 | 1 | 2 | 7 |
| 192.168.101.91 | archive.infowerks.com | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.101.92 |  | 4 | 0 | 2 | 0 | 0 | 2 |
| 192.168.101.93 | ilas1db04.infowerks.com | 5 | 0 | 3 | 0 | 0 | 2 |
| 192.168.101.111 | ilas1dc01.infowerks.com | 9 | 0 | 1 | 1 | 0 | 7 |
| 192.168.101.112 | icage0dc02.infowerks.com | 9 | 0 | 1 | 1 | 0 | 7 |
| 192.168.101.114 |  | 12 | 0 | 3 | 0 | 0 | 9 |
| 192.168.101.115 |  | 4 | 0 | 3 | 0 | 0 | 1 |
| 192.168.101.122 | ilas1drn12.infowerks.com | 7 | 0 | 0 | 1 | 0 | 6 |
| 192.168.101.123 | ilas1drn13.infowerks.com | 30 | 0 | 16 | 4 | 0 | 10 |
| 192.168.101.125 | ilas1drn15.infowerks.com | 30 | 0 | 16 | 4 | 0 | 10 |
| 192.168.101.141 | ilas1wks09.infowerks.com | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.101.152 | ilas3irun15.infowerks.com | 1 | 0 | 0 | 0 | 0 | 1 |
| 192.168.101.154 | ilas3wks46.infowerks.com | 21 | 0 | 10 | 2 | 0 | 9 |
| 192.168.101.155 | ilas1iruntst1.infowerks.com | 5 | 0 | 0 | 1 | 0 | 4 |
| 192.168.101.159 | iwnv-w-wks-lvillegas.infowerks.com | 6 | 0 | 0 | 1 | 0 | 5 |
| 192.168.101.160 | iwnv-w-wks-vminnick.infowerks.com | 6 | 0 | 0 | 1 | 0 | 5 |
| 192.168.101.175 | isql1.infowerks.com | 8 | 0 | 0 | 1 | 0 | 7 |
| 192.168.101.180 | ilas3db142.infowerks.com | 28 | 0 | 16 | 3 | 0 | 9 |
| 192.168.101.181 | ilas3db161.infowerks.com | 21 | 0 | 9 | 3 | 0 | 9 |
| 192.168.101.183 | ilas3irun04.infowerks.com | 28 | 0 | 12 | 6 | 0 | 10 |
| 192.168.101.184 | ilas3db140.infowerks.com | 13 | 0 | 4 | 1 | 0 | 8 |
| 192.168.101.185 | ilas3stor01.infowerks.com | 13 | 0 | 4 | 1 | 0 | 8 |
| 192.168.101.186 | ilas3db154.infowerks.com | 18 | 0 | 3 | 4 | 0 | 11 |
| 192.168.101.187 | ilas2db10.infowerks.com | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.101.189 |  | 4 | 0 | 2 | 0 | 0 | 2 |
| 192.168.101.191 | ilas2pg01.infowerks.com | 14 | 0 | 5 | 1 | 0 | 8 |
| 192.168.101.192 | ilas3db160.infowerks.com | 14 | 0 | 2 | 2 | 0 | 10 |
| 192.168.101.193 | ilas3db162.infowerks.com | 16 | 0 | 5 | 2 | 0 | 9 |
| 192.168.101.194 | ilas1win1004.infowerks.com | 18 | 0 | 8 | 1 | 0 | 9 |
| 192.168.101.196 | ilas3db153.infowerks.com | 18 | 0 | 3 | 4 | 0 | 11 |
| 192.168.101.198 | ilas2img16.infowerks.com | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.101.200 |  | 12 | 0 | 3 | 4 | 0 | 5 |
| 192.168.101.205 | ilas1as04.infowerks.com | 6 | 0 | 0 | 1 | 0 | 5 |
| 192.168.101.206 | ilas4bcc2.infowerks.com | 10 | 0 | 2 | 1 | 1 | 6 |
| 192.168.101.208 | ilas2db07.infowerks.com | 7 | 0 | 3 | 0 | 0 | 4 |
| 192.168.101.215 |  | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.101.216 |  | 2 | 0 | 1 | 0 | 0 | 1 |
| 192.168.101.221 | ilas1as09 | 28 | 0 | 2 | 1 | 0 | 25 |
| 192.168.101.225 |  | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.101.232 | ilas2img15.infowerks.com | 7 | 0 | 0 | 1 | 0 | 6 |
| 192.168.101.250 |  | 7 | 0 | 3 | 0 | 0 | 4 |
| 192.168.101.253 | ilas2fs05.infowerks.com | 12 | 0 | 0 | 2 | 0 | 10 |
| 192.168.101.254 | ilas2fs05.infowerks.com | 12 | 0 | 0 | 2 | 0 | 10 |
| 192.168.199.0 |  | 2 | 0 | 0 | 0 | 0 | 2 |
| 192.168.199.1 |  | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.199.5 |  | 3 | 0 | 1 | 0 | 0 | 2 |
| 192.168.199.6 |  | 5 | 0 | 1 | 0 | 0 | 4 |
| 192.168.199.8 |  | 1 | 0 | 0 | 0 | 0 | 1 |
| 192.168.199.22 |  | 8 | 0 | 1 | 1 | 0 | 6 |
| 192.168.199.30 |  | 3 | 0 | 2 | 0 | 0 | 1 |
| 192.168.199.31 |  | 2 | 0 | 1 | 0 | 0 | 1 |
| 192.168.199.40 | ilas1wagsimg01.infowerks.com | 5 | 0 | 0 | 1 | 0 | 4 |
| 192.168.199.74 |  | 4 | 0 | 1 | 0 | 0 | 3 |
| 192.168.199.78 |  | 5 | 0 | 2 | 0 | 0 | 3 |
| 192.168.199.79 |  | 2 | 0 | 1 | 0 | 0 | 1 |
| 192.168.199.89 |  | 5 | 0 | 0 | 1 | 0 | 4 |
| 192.168.199.90 |  | 7 | 0 | 0 | 1 | 0 | 6 |
| 192.168.199.95 |  | 3 | 0 | 2 | 0 | 0 | 1 |
| 192.168.199.204 |  | 2 | 0 | 1 | 0 | 0 | 1 |

Subnet summary:
  - 192.168.101.0/24: 70 hosts
  - 192.168.100.0/24: 16 hosts
  - 192.168.199.0/24: 16 hosts

---

## 6. Quality of Detection (QoD) Values

| QoD | Count | Percent |
|-----|------:|--------:|
| 97 | 408 | 40.8% |
| 80 | 393 | 39.3% |
| 70 | 100 | 10.0% |
| 30 | 93 | 9.3% |
| 99 | 3 | 0.3% |
| 1 | 3 | 0.3% |

QoD reference: 100=exploit, 99=remote_vul, 98=remote_app, 97=package, 95=registry, 80=remote_banner, 70=remote_banner_unreliable, 50=remote_analysis, 30=remote_probe, 1=general_note

---

## 7. Solution Types

| Solution Type | Count | Percent |
|--------------|------:|--------:|
| (empty) | 492 | 49.2% |
| VendorFix | 266 | 26.6% |
| Mitigation | 228 | 22.8% |
| WillNotFix | 8 | 0.8% |
| Workaround | 5 | 0.5% |
| NoneAvailable | 1 | 0.1% |

---

## 8. Scan Task Information

Task name(s): Assessment-268111-Scan
Task ID(s): 94c2d7e1-4197-414b-b174-d5f67260ac72

---

## 9. NVT OID Analysis

Total unique NVT OIDs: 145

OID prefix distribution:

| OID Prefix | Count | Feed/Family |
|-----------|------:|-------------|
| 1.3.6.1.4.1.25623.1 | 1000 | Greenbone Community Feed (OpenVAS) |

Sample OID values (first 20):
  - 1.3.6.1.4.1.25623.1.0.102095
  - 1.3.6.1.4.1.25623.1.0.103681
  - 1.3.6.1.4.1.25623.1.0.104180
  - 1.3.6.1.4.1.25623.1.0.104204
  - 1.3.6.1.4.1.25623.1.0.104551
  - 1.3.6.1.4.1.25623.1.0.104654
  - 1.3.6.1.4.1.25623.1.0.10666
  - 1.3.6.1.4.1.25623.1.0.107013
  - 1.3.6.1.4.1.25623.1.0.107311
  - 1.3.6.1.4.1.25623.1.0.107312
  - 1.3.6.1.4.1.25623.1.0.10736
  - 1.3.6.1.4.1.25623.1.0.107652
  - 1.3.6.1.4.1.25623.1.0.108044
  - 1.3.6.1.4.1.25623.1.0.108134
  - 1.3.6.1.4.1.25623.1.0.108440
  - 1.3.6.1.4.1.25623.1.0.108442
  - 1.3.6.1.4.1.25623.1.0.108526
  - 1.3.6.1.4.1.25623.1.0.108975
  - 1.3.6.1.4.1.25623.1.0.10919
  - 1.3.6.1.4.1.25623.1.0.11238
  ... (145 total unique OIDs)

---

## 10. CVE References

Total unique CVEs referenced: 154

### 2001 (3 CVEs)

- CVE-2001-0361
- CVE-2001-0572
- CVE-2001-1473

### 2002 (1 CVEs)

- CVE-2002-20001

### 2016 (2 CVEs)

- CVE-2016-2335
- CVE-2016-4004

### 2017 (1 CVEs)

- CVE-2017-5638

### 2018 (7 CVEs)

- CVE-2018-10115
- CVE-2018-10172
- CVE-2018-11784
- CVE-2018-8014
- CVE-2018-8034
- CVE-2018-8037
- CVE-2018-8269

### 2019 (21 CVEs)

- CVE-2019-0199
- CVE-2019-0221
- CVE-2019-0232
- CVE-2019-0657
- CVE-2019-0820
- CVE-2019-0980
- CVE-2019-0981
- CVE-2019-0982
- CVE-2019-10072
- CVE-2019-1075
- CVE-2019-12418
- CVE-2019-1301
- CVE-2019-1302
- CVE-2019-17563
- CVE-2019-7090
- CVE-2019-7096
- CVE-2019-7108
- CVE-2019-7837
- CVE-2019-7845
- CVE-2019-8069
- CVE-2019-8070

### 2020 (13 CVEs)

- CVE-2020-1045
- CVE-2020-1108
- CVE-2020-11996
- CVE-2020-13934
- CVE-2020-13935
- CVE-2020-13943
- CVE-2020-17527
- CVE-2020-1935
- CVE-2020-1938
- CVE-2020-3757
- CVE-2020-9484
- CVE-2020-9633
- CVE-2020-9746

### 2021 (13 CVEs)

- CVE-2021-24112
- CVE-2021-24122
- CVE-2021-25122
- CVE-2021-25329
- CVE-2021-26423
- CVE-2021-26701
- CVE-2021-30640
- CVE-2021-31957
- CVE-2021-33037
- CVE-2021-34532
- CVE-2021-41079
- CVE-2021-42340
- CVE-2021-43980

### 2022 (15 CVEs)

- CVE-2022-23181
- CVE-2022-23267
- CVE-2022-25762
- CVE-2022-29117
- CVE-2022-29145
- CVE-2022-29885
- CVE-2022-30184
- CVE-2022-34305
- CVE-2022-34716
- CVE-2022-38010
- CVE-2022-40735
- CVE-2022-41089
- CVE-2022-42252
- CVE-2022-47111
- CVE-2022-47112

### 2023 (16 CVEs)

- CVE-2023-24998
- CVE-2023-28708
- CVE-2023-32324
- CVE-2023-36049
- CVE-2023-36435
- CVE-2023-36558
- CVE-2023-38171
- CVE-2023-40481
- CVE-2023-41080
- CVE-2023-42795
- CVE-2023-44487
- CVE-2023-4504
- CVE-2023-45648
- CVE-2023-46589
- CVE-2023-52168
- CVE-2023-52169

### 2024 (36 CVEs)

- CVE-2024-0056
- CVE-2024-0057
- CVE-2024-11477
- CVE-2024-11612
- CVE-2024-20672
- CVE-2024-21319
- CVE-2024-21386
- CVE-2024-21392
- CVE-2024-21409
- CVE-2024-21733
- CVE-2024-23672
- CVE-2024-24549
- CVE-2024-26190
- CVE-2024-30045
- CVE-2024-30046
- CVE-2024-30105
- CVE-2024-34750
- CVE-2024-35235
- CVE-2024-35264
- CVE-2024-38081
- CVE-2024-38095
- CVE-2024-38167
- CVE-2024-38168
- CVE-2024-38229
- CVE-2024-41996
- CVE-2024-43483
- CVE-2024-43484
- CVE-2024-43485
- CVE-2024-47076
- CVE-2024-47175
- CVE-2024-47176
- CVE-2024-47850
- CVE-2024-50379
- CVE-2024-52316
- CVE-2024-54677
- CVE-2024-56337

### 2025 (26 CVEs)

- CVE-2025-0411
- CVE-2025-11001
- CVE-2025-11002
- CVE-2025-24070
- CVE-2025-24813
- CVE-2025-26646
- CVE-2025-30399
- CVE-2025-31651
- CVE-2025-46701
- CVE-2025-48976
- CVE-2025-48988
- CVE-2025-48989
- CVE-2025-49125
- CVE-2025-52434
- CVE-2025-52520
- CVE-2025-53506
- CVE-2025-53816
- CVE-2025-53817
- CVE-2025-55188
- CVE-2025-55247
- CVE-2025-55248
- CVE-2025-55315
- CVE-2025-55668
- CVE-2025-58060
- CVE-2025-58364
- CVE-2025-8671

---

## 11. Scan Timestamp Range

Earliest: 2025-11-15T09:42:13+00:00
Latest:   2025-11-15T19:10:31+00:00
Duration: 9:28:18
          (9.5 hours)

Findings by hour:

| Hour (UTC) | Findings |
|-----------|----------:|
| 2025-11-15 09:00 | 142 |
| 2025-11-15 10:00 | 16 |
| 2025-11-15 11:00 | 71 |
| 2025-11-15 12:00 | 115 |
| 2025-11-15 13:00 | 22 |
| 2025-11-15 14:00 | 195 |
| 2025-11-15 15:00 | 115 |
| 2025-11-15 16:00 | 154 |
| 2025-11-15 17:00 | 111 |
| 2025-11-15 18:00 | 47 |
| 2025-11-15 19:00 | 12 |

---

## 12. Authentication Evidence

### NVTs containing SMB-related keywords

- 7zip Detection (Windows SMB Login)
- ASP.NET Core/.NET Core SDK Detection (Windows SMB Login)
- Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login)
- Adobe Products Detection (Windows SMB Login)
- Authenticated Scan / LSC Info Consolidation (Windows SMB Login)
- BIOS and Hardware Information Detection (Windows SMB Login)
- Cygwin Detection (Windows SMB Login)

### NVTs containing SSH-related keywords

- Deprecated SSH-1 Protocol Detection
- Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater)

### NVTs suggesting authenticated/credential-based checks

- 7zip Detection (Windows SMB Login)
- ASP.NET Core/.NET Core SDK Detection (Windows SMB Login)
- Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login)
- Adobe Products Detection (Windows SMB Login)
- Authenticated Scan / LSC Info Consolidation (Windows SMB Login)
- BIOS and Hardware Information Detection (Windows SMB Login)
- Cygwin Detection (Windows SMB Login)
- Dell DRAC / iDRAC Default Credentials (HTTP)

### NVTs whose detection method or results reference authenticated access (SMB, WMI, Registry, etc.)

Total: 53 unique NVTs reference authentication-related terms in their
NVT name, detection method, or specific results. This includes NVTs that were
detected BECAUSE of authenticated access (e.g., .NET Core version detected via
Windows SMB Login, software found via Remote Registry, etc.).

NVTs with explicit auth keywords in their name:

- 7zip Detection (Windows SMB Login)
- ASP.NET Core/.NET Core SDK Detection (Windows SMB Login)
- Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login)
- Adobe Products Detection (Windows SMB Login)
- Authenticated Scan / LSC Info Consolidation (Windows SMB Login)
- BIOS and Hardware Information Detection (Windows SMB Login)
- Cygwin Detection (Windows SMB Login)
- Dell DRAC / iDRAC Default Credentials (HTTP)

Plus 45 additional NVTs that reference auth terms in their
detection method or result details (e.g., version detected via SMB).


### Credential status check results (one example per NVT)

**7zip Detection (Windows SMB Login)** -- 46 findings across 43 hosts
  Example (IP 192.168.101.88):
  Detected 7-Zip 9.20 (x64 edition)

Version:       9.20
Location:      Unable to find the install location
CPE:           cpe:/a:7-zip:7-zip:x64:9.20

Concluded from version/product identification result:
9.20

**ASP.NET Core/.NET Core SDK Detection (Windows SMB Login)** -- 45 findings across 19 hosts
  Example (IP 192.168.100.165):
  Detected .NET Core SDK

Version:       2.1.526
Location:      Could not find the install location from registry
CPE:           cpe:/a:microsoft:.netcore_sdk:x64:2.1.526

Concluded from version/product identification result:
.NET Core SDK 2.1.526

**Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login)** -- 8 findings across 8 hosts
  Example (IP 192.168.101.154):
  Detected Adobe Flash Player within IE/Edge

Version:       32.0.0.255
Location:      C:\WINDOWS\SysWOW64
CPE:           cpe:/a:adobe:flash_player_internet_explorer:32.0.0.255

Concluded from version/product identification result:
32.0.0.255

**Adobe Products Detection (Windows SMB Login)** -- 10 findings across 10 hosts
  Example (IP 192.168.100.171):
  Detected Adobe Acrobat (64-bit)

Version:       25.001.20844
Location:      C:\Program Files\Adobe\Acrobat DC\
CPE:           cpe:/a:adobe:acrobat:25.001.20844

Concluded from version/product identification result:
25.001.20844

**Authenticated Scan / LSC Info Consolidation (Windows SMB Login)** -- 62 findings across 60 hosts
  Example (IP 192.168.101.83):
  Description (Knowledge base entry)                                                              : Value/Content
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**BIOS and Hardware Information Detection (Windows SMB Login)** -- 48 findings across 47 hosts
  Example (IP 192.168.101.69):
  BIOS version: 1.0.2
BIOS Vendor: Dell Inc.
Base Board version: A02
Base Board Manufacturer: Dell Inc.
Base Board Product Name: 0PJPW3

**Cygwin Detection (Windows SMB Login)** -- 1 findings across 1 hosts
  Example (IP 192.168.100.160):
  Detected Cygwin

Version:       Unknown
Location:      C:\cygwin64
CPE:           cpe:/a:redhat:cygwin:x64

**Dell DRAC / iDRAC Default Credentials (HTTP)** -- 1 findings across 1 hosts
  Example (IP 192.168.101.208):
  It was possible to login with username 'root' and password 'calvin'.

Vulnerable URL: https://ilas2db07.infowerks.com/data/login
Result:         HTTP 200/201 status code and matching response: <authResult>0</authResult>

### Authentication Assessment Summary

Evidence suggests this was an AUTHENTICATED scan:
  - SMB Login/Windows Management NVTs are present
  - 411 findings with QoD >= 95 (may indicate some authenticated checks)

---

## Appendix A: Top 30 Most Common NVTs (by finding count)

| # | NVT Name | Count | Severity |
|--:|---------|------:|---------|
| 1 | CPE Inventory | 101 | Log |
| 2 | Allowed HTTP Methods Enumeration | 89 | Log |
| 3 | DCE/RPC and MSRPC Services Enumeration Reporting | 77 | Log |
| 4 | Authenticated Scan / LSC Info Consolidation (Windows SMB Login) | 62 | Log |
| 5 | DCE/RPC and MSRPC Services Enumeration | 59 | Log |
| 6 | BIOS and Hardware Information Detection (Windows SMB Login) | 48 | Log |
| 7 | 7zip Detection (Windows SMB Login) | 46 | Log |
| 8 | ASP.NET Core/.NET Core SDK Detection (Windows SMB Login) | 45 | Log |
| 9 | Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater) | 45 | High |
| 10 | Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater) | 39 | High |
| 11 | Check for Windows 10 Cortana Search | 26 | Log |
| 12 | Check open ports | 21 | Log |
| 13 | .NET Core Denial of Service And Information Disclosure Vulnerabilities - Windows | 12 | High |
| 14 | .NET Core Denial of Service Vulnerability (Jun 2021) | 12 | Medium |
| 15 | .NET Core Multiple Vulnerabilities (Oct 2025) | 11 | High |
| 16 | Adobe Products Detection (Windows SMB Login) | 10 | Log |
| 17 | Anti-Scanner Defenses (HTTP) | 10 | Log |
| 18 | Dell EMC OpenManage Server Administrator (OMSA) Detection (HTTP) | 10 | Log |
| 19 | .NET Core RCE Vulnerability (Jan 2025) | 9 | High |
| 20 | .NET Core RCE Vulnerability (January-1 2025) | 9 | High |
| 21 | .NET Core Security Feature Bypass Vulnerability (Sep 2020) | 9 | High |
| 22 | Adobe Flash Player End of Life (EOL) Detection | 8 | High |
| 23 | Adobe Flash Player Within Microsoft IE and Edge Detection (Windows SMB Login) | 8 | Log |
| 24 | .NET Core Elevation of Privilege Vulnerability (Mar 2025) | 7 | High |
| 25 | .NET Core RCE Vulnerability (Jun 2025) | 7 | High |
| 26 | .NET Core Spoofing Vulnerability (May 2025) | 7 | High |
| 27 | Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-30) - Windows | 7 | High |
| 28 | Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-58) - Windows | 7 | High |
| 29 | favicon.ico Based Fingerprinting (HTTP) | 6 | Log |
| 30 | .NET Core Information Disclosure Vulnerability (KB5015424) | 6 | Medium |

---

## Appendix B: Actionable Findings Summary (non-Log severity)

Total actionable findings: 431

| NVT Name | Severity | CVSS | Hosts Affected | Total Findings |
|---------|---------|------|---------------:|---------------:|
| 7-Zip Multiple Vulnerabilities - Windows | High | 10.0 | 1 | 1 |
| Adobe Flash Player End of Life (EOL) Detection | High | 10.0 | 8 | 8 |
| Apache Tomcat End of Life (EOL) Detection - Windows | High | 10.0 | 1 | 1 |
| .NET Core Multiple Vulnerabilities (Oct 2025) | High | 9.9 | 7 | 11 |
| .NET Core Multiple Vulnerabilities (KB5033734) | High | 9.8 | 1 | 1 |
| .NET Core Multiple Vulnerabilities - Windows | High | 9.8 | 2 | 2 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-19) - Windows | High | 9.8 | 1 | 1 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-46) - Windows | High | 9.8 | 1 | 1 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-30) - Windows | High | 9.8 | 7 | 7 |
| Apache Struts Security Update (S2-045) - Active Check | High | 9.8 | 1 | 2 |
| Apache Tomcat CORS Filter Setting Security Bypass Vulnerability | High | 9.8 | 1 | 1 |
| Apache Tomcat Multiple Vulnerabilities (Feb 2020) - Windows | High | 9.8 | 1 | 1 |
| Apache Tomcat RCE Vulnerability (Mar 2025) - Windows | High | 9.8 | 1 | 2 |
| Apache Tomcat Rewrite Rule Bypass Vulnerability (Apr 2025) - Windows | High | 9.8 | 1 | 2 |
| CUPS Multiple Vulnerabilities (Sep/Oct 2024) | High | 9.8 | 1 | 1 |
| 7-Zip RCE Vulnerability - Windows | High | 9.3 | 1 | 1 |
| .NET Core Multiple Vulnerabilities (Sep 2019) | High | 8.8 | 1 | 1 |
| .NET Core SDK Multiple Vulnerabilities (Sep 2019) | High | 8.8 | 1 | 1 |
| 7zip Authentication Bypass Vulnerability - Windows | High | 8.8 | 1 | 1 |
| 7Zip UDF CInArchive::ReadFileItem Code Execution Vulnerability | High | 8.8 | 1 | 1 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-26) - Windows | High | 8.8 | 1 | 1 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-30) - Windows | High | 8.8 | 1 | 1 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-06) - Windows | High | 8.8 | 4 | 4 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-58) - Windows | High | 8.8 | 7 | 7 |
| Apache Tomcat Request Mix-up Vulnerability (May 2022) - Windows | High | 8.6 | 1 | 2 |
| .NET Core Multiple Vulnerabilities (KB5041081) | High | 8.1 | 2 | 2 |
| .NET Core Multiple Vulnerabilities (KB5045993) | High | 8.1 | 2 | 2 |
| .NET Core RCE Vulnerability (Jan 2025) | High | 8.1 | 5 | 9 |
| .NET Core RCE Vulnerability (January-1 2025) | High | 8.1 | 5 | 9 |
| Apache Tomcat RCE Vulnerability (Apr 2019) - Windows | High | 8.1 | 1 | 1 |
| .NET Core Spoofing Vulnerability (May 2025) | High | 8.0 | 5 | 7 |
| .NET Core Denial of Service Vulnerability - Windows | High | 7.8 | 5 | 5 |
| .NET Core Remote Code Execution Vulnerability - Windows | High | 7.8 | 5 | 5 |
| 7-Zip Qcow Handler Infinite Loop DoS Vulnerability - Windows | High | 7.8 | 1 | 1 |
| 7-Zip Zstandard Decompression Integer Underflow Vulnerability - Windows | High | 7.8 | 1 | 1 |
| 7zip RAR Denial of Service Vulnerability - Windows | High | 7.8 | 1 | 1 |
| Apache Tomcat DoS Vulnerability (Jul 2024) - Windows | High | 7.8 | 1 | 2 |
| Apache Tomcat DoS Vulnerability (Jul 2025) - Windows | High | 7.8 | 1 | 2 |
| Apache Tomcat HTTP/2 Protocol DoS Vulnerability (MadeYouReset) - Windows | High | 7.8 | 1 | 2 |
| Apache Tomcat Multiple DoS Vulnerabilities (Jul 2025) - Windows | High | 7.8 | 1 | 2 |
| Apache Tomcat Multiple Vulnerabilities (Jun 2025) - Windows | High | 7.8 | 1 | 2 |
| Apache Tomcat Session Fixation Vulnerability (Aug 2025) - Windows | High | 7.8 | 1 | 2 |
| .NET Core Denial of Service And Information Disclosure Vulnerabilities - Windows | High | 7.5 | 6 | 12 |
| .NET Core DoS Vulnerability (Feb 2024) - Windows | High | 7.5 | 2 | 2 |
| .NET Core DoS Vulnerability (May 2020) | High | 7.5 | 1 | 1 |
| .NET Core Multiple Denial of Service Vulnerabilities (KB5014326) | High | 7.5 | 6 | 6 |
| .NET Core Multiple Denial of Service Vulnerabilities (KB5036452) | High | 7.5 | 1 | 1 |
| .NET Core Multiple DoS Vulnerabilities - Windows | High | 7.5 | 1 | 1 |
| .NET Core Multiple DoS Vulnerabilities-01 (May 2019) | High | 7.5 | 2 | 2 |
| .NET Core Multiple DoS Vulnerabilities-02 (May 2019) | High | 7.5 | 1 | 1 |
| .NET Core Multiple Vulnerabilities (KB5042132) | High | 7.5 | 2 | 2 |
| .NET Core OData Denial of Service Vulnerability - Windows | High | 7.5 | 1 | 1 |
| .NET Core RCE Vulnerability (Jun 2025) | High | 7.5 | 5 | 7 |
| .NET Core SDK DoS Vulnerability (May 2020) | High | 7.5 | 1 | 1 |
| .NET Core SDK Multiple DoS Vulnerabilities-01 (May 2019) | High | 7.5 | 2 | 2 |
| .NET Core SDK Multiple DoS Vulnerabilities-02 (May 2019) | High | 7.5 | 1 | 1 |
| .NET Core SDK Security Feature Bypass Vulnerability (Sep 2020) | High | 7.5 | 1 | 1 |
| .NET Core Security Feature Bypass Vulnerability (Sep 2020) | High | 7.5 | 5 | 9 |
| 7-Zip Multiple Vulnerabilities (Jul 2025) - Windows | High | 7.5 | 2 | 2 |
| Apache Tomcat Hostname Verification Security Bypass Vulnerability - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat Clustering DoS Vulnerability (May 2022) | High | 7.5 | 1 | 2 |
| Apache Tomcat DoS Vulnerability (Feb 2023) - Windows | High | 7.5 | 1 | 2 |
| Apache Tomcat DoS Vulnerability (Jun 2019) - Windows | High | 7.5 | 1 | 2 |
| Apache Tomcat DoS Vulnerability (Jun 2020) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat DoS Vulnerability (Mar 2019) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat DoS Vulnerability (Oct 2021) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat DoS Vulnerability (Sep 2021) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat HTTP/2 Vulnerability (Dec 2020) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat Information Disclosure Vulnerability (Mar 2021) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat Multiple DoS Vulnerabilities (Jul 2020) - Windows | High | 7.5 | 1 | 1 |
| Apache Tomcat Multiple Vulnerabilities (Oct 2023) - Windows | High | 7.5 | 1 | 2 |
| Apache Tomcat Request Smuggling Vulnerability (Nov 2023) - Windows | High | 7.5 | 1 | 2 |
| Apache Tomcat Request Smuggling Vulnerability (Oct 2022) - Windows | High | 7.5 | 1 | 2 |
| Apache Tomcat Session Fixation Vulnerability (Dec 2019) - Windows | High | 7.5 | 1 | 1 |
| Dell DRAC / iDRAC Default Credentials (HTTP) | High | 7.5 | 1 | 1 |
| Deprecated SSH-1 Protocol Detection | High | 7.5 | 3 | 3 |
| Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater) | High | 7.5 | 37 | 39 |
| Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater) | High | 7.5 | 43 | 45 |
| .NET Core Privilege Escalation Vulnerability (KB5037337) | High | 7.3 | 1 | 1 |
| .NET Core Privilege Escalation Vulnerability (KB5037338) | High | 7.3 | 2 | 2 |
| .NET Core Elevation of Privilege Vulnerability (Mar 2025) | High | 7.0 | 5 | 7 |
| 7-Zip Mark-of-the-Web Bypass Vulnerability (Jan 2025) - Windows | High | 7.0 | 2 | 2 |
| Apache Tomcat Local Privilege Escalation Vulnerability (Jan 2022) - Windows | High | 7.0 | 1 | 1 |
| Apache Tomcat Privilege Escalation Vulnerability (Dec 2019) - Windows | High | 7.0 | 1 | 1 |
| Apache Tomcat RCE Vulnerability (Mar 2021) - Windows | High | 7.0 | 1 | 1 |
| Apache Tomcat RCE Vulnerability (May 2020) - Windows | High | 7.0 | 1 | 1 |
| CUPS < 2.4.7 Buffer Overflow Vulnerability | High | 7.0 | 1 | 1 |
| CUPS < 2.4.13 Multiple Vulnerabilities | Medium | 6.8 | 1 | 1 |
| CUPS < 2.4.9 File Permission Vulnerability | Medium | 6.7 | 1 | 1 |
| Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB19-06) - Windows | Medium | 6.5 | 1 | 1 |
| Apache Tomcat JNDI Realm Authentication Weakness Vulnerability (Jul 2021) - Windows | Medium | 6.5 | 1 | 1 |
| Apache Tomcat Authentication Bypass Vulnerability (Nov 2024) - Windows | Medium | 6.4 | 1 | 2 |
| .NET Core Multiple Vulnerabilities (KB5038351) | Medium | 6.3 | 3 | 4 |
| .NET Core SDK Spoofing Vulnerability (Jul 2019) | Medium | 6.1 | 1 | 1 |
| .NET Core Spoofing Vulnerability (Jul 2019) | Medium | 6.1 | 1 | 1 |
| Apache Tomcat Open Redirect Vulnerability (Aug 2023) - Windows | Medium | 6.1 | 1 | 2 |
| Apache Tomcat XSS Vulnerability (Jun 2022) - Windows | Medium | 6.1 | 1 | 1 |
| Apache Tomcat XSS Vulnerability (May 2019) - Windows | Medium | 6.1 | 1 | 1 |
| .NET Core Denial of Service Vulnerability (Jun 2021) | Medium | 5.9 | 12 | 12 |
| .NET Core Information Disclosure Vulnerabilities - Windows | Medium | 5.9 | 5 | 5 |
| .NET Core SDK Spoofing Vulnerability (Feb 2019) | Medium | 5.9 | 3 | 3 |
| .NET Core Spoofing Vulnerability (Feb 2019) | Medium | 5.9 | 3 | 3 |
| Apache Tomcat NIO/NIO2 Connectors Information Disclosure Vulnerability - Windows | Medium | 5.9 | 1 | 1 |
| Apache Tomcat Information Disclosure Vulnerability (Jan 2021) - Windows | Medium | 5.9 | 1 | 1 |
| .NET Core Information Disclosure Vulnerability (KB5015424) | Medium | 5.5 | 6 | 6 |
| CUPS < 2.4.3 DoS Vulnerability | Medium | 5.5 | 1 | 1 |
| Apache Tomcat HTTP Request Smuggling Vulnerability (Jul 2021) - Windows | Medium | 5.3 | 1 | 1 |
| Apache Tomcat Information Disclosure Vulnerability (Jan 2024) - Windows | Medium | 5.3 | 1 | 1 |
| Apache Tomcat CGI Security Constraint Bypass Vulnerability (May 2025) - Windows | Medium | 5.0 | 1 | 2 |
| Apache Tomcat Multiple DoS Vulnerabilities (Mar 2024) - Windows | Medium | 5.0 | 1 | 2 |
| Apache Tomcat Multiple Vulnerabilities (Dec 2024) - Windows | Medium | 5.0 | 1 | 2 |
| Backup File Scanner (HTTP) - Unreliable Detection Reporting | Medium | 5.0 | 4 | 4 |
| DCE/RPC and MSRPC Services Enumeration Reporting | Medium | 5.0 | 59 | 59 |
| Dell OpenManage Server Administrator Directory Traversal Vulnerability (Apr 2016) | Medium | 4.9 | 2 | 2 |
| AppleShare IP / Apple Filing Protocol (AFP) Unencrypted Cleartext Login | Medium | 4.8 | 1 | 1 |
| Cleartext Transmission of Sensitive Information via HTTP | Medium | 4.8 | 5 | 5 |
| Apache Tomcat HTTP/2 Vulnerability (Oct 2020) - Windows | Medium | 4.3 | 1 | 1 |
| Apache Tomcat Information Disclosure Vulnerability (Mar 2023) - Windows | Medium | 4.3 | 1 | 2 |
| Apache Tomcat Open Redirect Vulnerability - Windows | Medium | 4.3 | 1 | 1 |
| Apache Tomcat Information Disclosure Vulnerability (Sep 2022) - Windows | Low | 3.7 | 1 | 2 |
| 7-Zip Multiple Vulnerabilities (Apr 2025) - Windows | Low | 3.3 | 1 | 1 |
| 7-Zip Arbitrary File Write Vulnerability (Oct 2025) - Windows | Low | 2.1 | 2 | 2 |

---

## Appendix C: Greenbone Community Edition Replication Notes

Based on the analysis of this scan:

1. **Scan Task Name**: Assessment-268111-Scan
2. **Target IPs**: 102 hosts across 3 subnet(s)
   - 192.168.100.0/24
   - 192.168.101.0/24
   - 192.168.199.0/24
3. **NVT Feed**: All OIDs begin with 1.3.6.1.4.1.25623 (Greenbone Community Feed)
4. **Total unique NVTs executed**: 144
5. **Unique OIDs**: 145
6. **Likely Scan Config**: Full and fast or custom config
7. **Credentials**: Authenticated scan -- configure SMB and/or SSH credentials in target
8. **Port List**: 22, 23, 25, 80, 135, 443, 548, 631, 1022, 1311, 1536, 1537, 1538, 1539, 1540, 1541, 1542, 1572, 1587, 2103, 2105, 2107, 3002, 3003, 3033, 3232, 3269, 3389, 4444, 5000, 5432, 5989, 7070, 8084, 8088, 8090, 9084, 9087, 9090, 9443, 10080, 20003, 47001

To replicate this scan in Greenbone Community Edition:

  a. Create a Target with the IP list above
  b. Use the 'Full and fast' scan configuration (covers all detected NVT families)
  c. Add SMB credentials (domain admin or local admin) to the target
  d. Create a Task linking the target and scan config
  e. Start the task

