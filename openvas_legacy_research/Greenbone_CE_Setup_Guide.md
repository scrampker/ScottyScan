# Greenbone Community Edition Setup Guide
# Replicating the Legacy vPenTest/OpenVAS Scan Configuration

This guide walks through setting up Greenbone Community Edition (GCE) to
replicate the scan coverage previously delivered by the Vonahi Security
vPenTest platform. The legacy platform used OpenVAS/Greenbone VT feed 23.20.1
with Nmap 7.95 for discovery, running from a Linux Docker VM.

Reference deliverables analyzed:
- Combined-Deliverables_2025-11-15/ (November 15, 2025 assessment)
- Executive summary, vulnerability report, nmap scans, OpenVAS CSV/XML exports

---

## TABLE OF CONTENTS

1. What the Legacy Scanner Was Actually Doing
2. Prerequisites
3. Install Greenbone Community Edition
4. Initial Feed Sync (Critical -- Do This First)
5. Create the Target Definition
6. Configure SMB Credentials (Authenticated Scanning)
7. Create the Port List
8. Select the Scan Configuration
9. Create and Run the Scan Task
10. Export Results in Matching Format
11. Result Comparison Checklist
12. Known Gaps Between Legacy and Community Edition
13. Scheduling Monthly Scans
14. Appendix A: Full TCP Port List From Legacy Scanner
15. Appendix B: Legacy Scan Statistics for Comparison

---

## 1. WHAT THE LEGACY SCANNER WAS ACTUALLY DOING

The Vonahi vPenTest platform ran a two-phase automated assessment:

PHASE 1 -- Host Discovery (Nmap):
- Nmap 7.95 with flags: -Pn -T3 -n -sSU
- TCP SYN scan + UDP scan combined
- 499 specific TCP ports + 6 UDP ports (NOT a full 65535 sweep)
- All hosts treated as up (-Pn), no DNS resolution (-n)
- Duration: ~3.5 minutes for 768 target IPs

PHASE 2 -- Vulnerability Assessment (OpenVAS):
- OpenVAS with Greenbone Community Feed (VT version 23.20.1)
- Authenticated scanning on Windows hosts via SMB login
- Unauthenticated network scanning on Linux/appliance hosts
- Active exploitation checks included (e.g., Apache Struts S2-045)
- Duration: ~9.5 hours for 102 hosts with open ports
- 1000 total result records, 144 unique NVT checks, 154 unique CVEs

KEY FINDING: All NVT OIDs in the export use the 1.3.6.1.4.1.25623 prefix,
which is the Greenbone Community Feed. This means the Community Edition
should have access to the SAME vulnerability tests that were used in the
legacy scan. You are not losing coverage by switching from vPenTest to GCE
for this particular check set.

---

## 2. PREREQUISITES

Hardware requirements for Greenbone Community Edition:
- Minimum 4 CPU cores (8 recommended for 100+ host scans)
- Minimum 8 GB RAM (16 GB recommended)
- Minimum 40 GB disk (the VT feed alone is 10+ GB)
- Network access to all target subnets

Software requirements:
- Docker and Docker Compose (recommended deployment method)
- OR a dedicated Debian/Ubuntu VM for source install
- A web browser for the Greenbone Security Assistant (GSA) web UI

Network requirements:
- Scanner must be on a network segment that can reach:
  - 192.168.100.0/24 (workstations, servers)
  - 192.168.101.0/24 (servers, infrastructure)
  - 192.168.199.0/24 (remote site -- may need routing/VPN)
- Scanner needs outbound HTTPS to pull the VT feed from Greenbone

Account requirements:
- Domain admin or local admin credentials for Windows SMB authenticated scanning
- These are the same credentials the legacy scanner used for "Windows SMB Login"
  detections (7-Zip, .NET Core, Adobe, BIOS info, etc.)

---

## 3. INSTALL GREENBONE COMMUNITY EDITION

### Option A: Docker Compose (Recommended)

This is the officially supported deployment method. Follow the Greenbone
documentation at: https://greenbone.github.io/docs/latest/

Summary of steps:

    # Create a working directory
    mkdir -p /opt/greenbone && cd /opt/greenbone

    # Download the docker-compose file from the Greenbone docs
    # (check the official docs for the latest version URL)
    curl -fsSL https://greenbone.github.io/docs/latest/_static/docker-compose.yml \
      -o docker-compose.yml

    # Pull and start all containers
    docker compose up -d

    # Wait for initial startup (several minutes)
    docker compose logs -f

The stack includes:
- gvmd (Greenbone Vulnerability Manager daemon)
- openvas-scanner (the actual scanning engine)
- gsad (Greenbone Security Assistant -- web UI)
- pg-gvm (PostgreSQL database)
- ospd-openvas (OSP daemon bridging gvmd to the scanner)
- notus-scanner (local security check processor)
- mqtt-broker (internal messaging)

Default login after startup:
- URL: https://<scanner-ip>:9392
- Username: admin
- Password: admin (CHANGE THIS IMMEDIATELY)

To set the admin password:

    docker compose exec gvmd gvmd --user=admin --new-password=YourSecurePassword

### Option B: Source/Package Install

For a dedicated VM install (Debian 12 / Ubuntu 22.04+), follow the
Greenbone source build documentation. This is more complex but gives you
more control over resource allocation.

---

## 4. INITIAL FEED SYNC (CRITICAL -- DO THIS FIRST)

The VT feed is what makes OpenVAS useful. Without it, the scanner has zero
vulnerability checks. The initial sync takes 30-60 minutes and downloads
10+ GB of data.

### Docker deployment:

    # The feed sync runs automatically on first startup.
    # Monitor progress:
    docker compose logs -f greenbone-feed-sync

    # To manually trigger a feed update:
    docker compose exec greenbone-feed-sync greenbone-feed-sync

### Verify feed sync is complete:

1. Log into the GSA web UI
2. Go to Administration > Feed Status
3. All feeds should show status "Current" with a recent timestamp:
   - NVT (Network Vulnerability Tests) -- this is the main one
   - SCAP (CVE/CPE data)
   - CERT (advisory data)
   - GVMD_DATA (scan configs, port lists, etc.)

DO NOT proceed to create scan tasks until the NVT feed shows "Current".
Scanning with an empty or partial feed will produce incomplete results.

### Feed update schedule:

The Greenbone Community Feed updates daily. Set up a cron job or systemd
timer to sync the feed at least once per day:

    # Example cron entry (Docker deployment):
    0 3 * * * cd /opt/greenbone && docker compose exec -T greenbone-feed-sync greenbone-feed-sync

The legacy scanner used VT feed version 23.20.1 (November 2025). Your new
instance will have a newer feed with additional checks -- this is a good
thing.

---

## 5. CREATE THE TARGET DEFINITION

The legacy scan covered three subnet ranges. Create a target in GCE that
matches this scope.

### Via GSA Web UI:

1. Navigate to Configuration > Targets
2. Click the star icon (New Target)
3. Fill in:

   Name: Monthly Internal Network Scan
   Comment: Replicating legacy vPenTest Assessment-268111-Scan scope

   Hosts -- Manual:
     192.168.100.0/24, 192.168.101.0/24, 192.168.199.0/24

   Exclude Hosts: (leave empty -- legacy scan had no exclusions)

   Port List: [Select the custom port list created in Step 7]

   Alive Test: Consider Alive
     NOTE: The legacy scanner used Nmap -Pn which treats ALL hosts as alive.
     In GCE, "Consider Alive" is the equivalent. However, this will cause
     the scanner to attempt vulnerability checks on every IP in the range,
     including dead IPs. This wastes time.

     RECOMMENDED ALTERNATIVE: Use "ICMP, TCP-ACK Service & ARP Ping" instead.
     This performs actual host discovery first, which is faster and more
     accurate. The tradeoff is that hosts behind firewalls that block ICMP
     may be missed -- but the legacy scan had this same problem (239 phantom
     hosts in 192.168.199.0/24 from -Pn).

   Credentials for authenticated checks:
     SMB: [Select the SMB credential created in Step 6]

4. Click Create

### Via gvm-cli (command line):

    # Create target via GMP protocol
    gvm-cli --gmp-username admin --gmp-password <password> \
      socket --socketpath /run/gvmd/gvmd.sock \
      --xml '<create_target>
        <name>Monthly Internal Network Scan</name>
        <hosts>192.168.100.0/24, 192.168.101.0/24, 192.168.199.0/24</hosts>
        <alive_tests>Consider Alive</alive_tests>
      </create_target>'

---

## 6. CONFIGURE SMB CREDENTIALS (AUTHENTICATED SCANNING)

The legacy scan performed authenticated Windows scanning via SMB login.
This is what enabled detection of installed software versions (7-Zip,
.NET Core, Adobe Flash, etc.) that are not exposed via network services.

Without SMB credentials, you will MISS approximately 40% of the findings
from the legacy scan (all the "Windows SMB Login" detections).

### Create SMB Credential:

1. Navigate to Configuration > Credentials
2. Click the star icon (New Credential)
3. Fill in:

   Name: Domain Admin - SMB Scanning
   Comment: For authenticated Windows vulnerability scanning
   Type: Username + Password

   Login: INFOWERKS\<admin-username>
     (Use the same domain admin account the legacy scanner used.
      Format: DOMAIN\username or username@domain.com)

   Password: <the domain admin password>

4. Click Create

### Link to Target:

Go back to Configuration > Targets, edit the target created in Step 5,
and set the SMB credential under "Credentials for authenticated checks."

### Credential requirements on target hosts:

For SMB authenticated scanning to work, the following must be true on
each Windows target:

- The credential account must have local admin or domain admin privileges
- File and Printer Sharing must be enabled (port 445 reachable)
- The Remote Registry service should be running (or set to Manual and
  startable remotely) -- this is how OpenVAS reads installed software versions
- Windows Firewall must allow SMB (TCP 445) and WMI (TCP 135 + dynamic
  RPC ports) from the scanner IP
- If using a domain account, the scanner must be able to resolve the domain
  (DNS must work from the scanner to the AD domain controllers)

### Optional: SSH Credential for Linux Hosts

The legacy scan did NOT perform authenticated scanning on Linux hosts.
This is a gap you can improve on. If you want deeper Linux vulnerability
detection:

1. Create an SSH credential (username + key or username + password)
2. Ensure the account has sudo or root access on Linux hosts
3. Add it to the target definition under SSH credential

This will enable package-level vulnerability detection on Linux, similar
to what "Windows SMB Login" does for Windows.

---

## 7. CREATE THE PORT LIST

The legacy scanner used a custom list of 499 TCP ports + 6 UDP ports.
This is NOT one of the built-in Greenbone port lists.

### Option A: Use Built-in "All TCP and Nmap top 100 UDP" (Easiest)

This built-in port list scans all 65535 TCP ports plus the top 100 UDP
ports. It is MORE comprehensive than the legacy scan (which only did 499
TCP ports) but will take longer.

Pros: Catches everything the legacy scan would, plus more
Cons: Scan will take longer (possibly 12-16 hours vs 9.5 hours)

### Option B: Create a Custom Port List Matching Legacy (Exact Match)

If you want to replicate the exact same port coverage:

1. Navigate to Configuration > Port Lists
2. Click the star icon (New Port List)
3. Fill in:

   Name: Legacy vPenTest Enterprise Ports (499 TCP + 6 UDP)
   Comment: Matches the Nmap port list from vPenTest Assessment-268111

   Port Ranges (Manual):

   TCP:
   1,7,9,13,19,21,22,23,25,37,42,43,49,53,67,69,70,79,80,81,82,83,84,
   85,88,89,90,99,100,106,110,111,113,119,123,135,139,143,161,179,199,
   211,217,254,255,259,264,280,311,340,389,401,402,404,407,425,427,443,
   444,445,458,464,465,475,497,500,502,512,513,514,515,520,524,541,543,
   548,554,555,563,587,593,616,617,623,625,631,636,646,648,666,667,668,
   683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,
   808,843,873,880,888,898,900,901,902,903,990,992,993,994,995,999,1000,
   1001,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,
   1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,
   1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,
   1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,
   1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,
   1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,
   1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,
   1110,1111,1112,1113,1117,1119,1121,1122,1128,1131,1138,1148,1169,
   1199,1211,1234,1241,1248,1271,1277,1311,1352,1433,1434,1443,1455,
   1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,
   1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,
   1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,
   1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,
   2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,
   2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,
   2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,
   2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,
   2323,2366,2381,2382,2393,2394,2399,2401,2492,2500,2522,2525,2557,
   2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,
   2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,
   3003,3005,3006,3007,3011,3013,3017,3030,3031,3050,3052,3071,3077,
   3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,
   3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,
   3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,
   3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,
   3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,
   4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,
   4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,
   5000,5001,5002,5003,5004,5009,5030,5033,5040,5050,5051,5054,5060,
   5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,
   5226,5269,5280,5298,5357,5405,5414,5431,5432,5433,5440,5500,5510,
   5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,
   5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,
   5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,
   5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,
   6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,
   6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,
   6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,
   6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,
   7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,
   7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,
   8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,
   8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,
   8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,
   8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,
   9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,
   9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9443,9485,
   9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,
   9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,
   10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,
   10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,
   12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,
   14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,
   16018,16080,17877,17988,18040,18101,18988,19101,19283,19315,19350,
   20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,
   25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,
   30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,
   32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,
   33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,
   44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,
   49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,
   49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,
   51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,
   55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,
   63331,64623,64680,65000,65129,65389

   UDP:
   88,161,389,500,623,5351

4. Click Create

### Option C: Use Built-in "All IANA Assigned TCP" (Good Compromise)

This scans all IANA-assigned TCP ports (~5000+ ports). More comprehensive
than the legacy 499 ports, less exhaustive than full 65535. Good balance
of coverage and speed.

RECOMMENDATION: Start with Option A ("All TCP and Nmap top 100 UDP") for
your first scan to establish a comprehensive baseline, then switch to the
custom port list (Option B) for ongoing monthly scans if scan duration is
a concern.

---

## 8. SELECT THE SCAN CONFIGURATION

Greenbone CE comes with several built-in scan configurations.

### Recommended: "Full and fast"

This is the most appropriate match for the legacy scan. It:
- Runs all NVT families that are safe (no destructive checks)
- Includes version detection, service enumeration, and vulnerability checks
- Uses Quality of Detection (QoD) threshold of 70% by default
- Performs authenticated checks when credentials are provided
- Includes active exploitation checks like Apache Struts S2-045

The legacy scan results show QoD values of 1, 30, 70, 80, 97, and 99,
which aligns with a comprehensive scan config.

### Alternative: "Full and fast ultimate"

Same as "Full and fast" but also includes:
- Checks that may crash target services
- More aggressive exploitation attempts
- Brute force checks

Only use this in maintenance windows when service disruption is acceptable.

### DO NOT use: "Discovery" or "Host Discovery"

These only enumerate hosts and services -- they do NOT run vulnerability
checks. They would miss all 431 actionable findings from the legacy scan.

### Adjusting QoD Threshold:

The legacy scan included findings with QoD as low as 1 (general_note).
The default GCE QoD filter threshold is 70%, which would hide some
findings. To match the legacy output:

1. When viewing scan results, adjust the filter to include lower QoD:
   - Change "min_qod=70" to "min_qod=1" in the results filter
2. Or create a custom scan config:
   - Clone "Full and fast"
   - Edit the clone
   - Under Scanner Preferences, set "Minimum QoD" to 1

---

## 9. CREATE AND RUN THE SCAN TASK

### Create the Task:

1. Navigate to Scans > Tasks
2. Click the star icon (New Task)
3. Fill in:

   Name: Monthly Internal Network Scan
   Comment: Replicating vPenTest Assessment-268111 configuration

   Scan Targets: [Select the target from Step 5]
   Scanner: OpenVAS Default
   Scan Config: Full and fast

   Schedule: [Optional -- see Step 13 for monthly scheduling]

   Alterable Task: Yes (allows re-running and editing)

   Network Source Interface: [Leave blank unless the scanner has multiple
     network interfaces -- then specify the interface on the target subnet,
     e.g., ens160]

   Order for target hosts: Random
     (The legacy scanner processed hosts somewhat sequentially. Random is
      better for load distribution.)

   Maximum concurrently executed NVTs per host: 4
     (Default. Increase to 8-10 if the scanner has 8+ CPU cores.)

   Maximum concurrently scanned hosts: 20
     (Default. The legacy scan processed ~102 hosts in 9.5 hours. Adjust
      based on your hardware. With 20 concurrent hosts on an 8-core/16GB
      system, expect 8-14 hours for ~100 hosts.)

4. Click Create

### Run the Task:

1. In the Tasks list, find your task
2. Click the green play button (Start)
3. Monitor progress in the task details view

### Expected Duration:

The legacy scan took approximately 9.5 hours to scan 102 hosts with
open ports. With GCE using "Full and fast" and similar hardware:

- If using the custom 499-port list: 8-12 hours
- If using "All TCP" port list: 12-18 hours
- Authenticated scanning adds ~2-5 minutes per Windows host

### Monitoring Progress:

- The task status bar shows overall percentage
- Click on the task name to see real-time results as they come in
- Check the "Results" tab for findings discovered so far
- If the scan appears stuck on a host, it may be waiting for TCP
  timeouts on filtered ports

---

## 10. EXPORT RESULTS IN MATCHING FORMAT

The legacy scan produced two key output files:
- detailedresults.csv (26 columns, the primary data file)
- detailedresults.xml (full OpenVAS XML report)

### Export CSV:

1. Navigate to Scans > Reports
2. Click on the completed scan report
3. Click the download icon (top right)
4. Select format: "CSV Results"
5. Adjust the filter if needed:
   - To match legacy output: set min_qod=1 and remove severity filters
   - To see only actionable findings: set min_qod=70 and severity > 0

### CSV Column Mapping (Legacy vs GCE):

The CSV export from GCE should have the same 26-column schema:

| Column | Legacy Name | GCE Name | Notes |
|--------|------------|----------|-------|
| 1 | IP | IP | Same |
| 2 | Hostname | Hostname | Same |
| 3 | Port | Port | Same |
| 4 | Port Protocol | Port Protocol | Same |
| 5 | CVSS | CVSS | Same (v2/v3) |
| 6 | Severity | Severity | Same (Log/Low/Med/High) |
| 7 | QoD | QoD | Same (1-100) |
| 8 | Solution Type | Solution Type | Same |
| 9 | NVT Name | NVT Name | Same |
| 10 | Summary | Summary | Same |
| 11 | Specific Result | Specific Result | Same |
| 12 | NVT OID | NVT OID | Same |
| 13 | CVEs | CVEs | Same |
| 14 | Task ID | Task ID | Different UUID |
| 15 | Task Name | Task Name | Your task name |
| 16 | Timestamp | Timestamp | ISO 8601 format |
| 17 | Result ID | Result ID | Different UUID |
| 18 | Impact | Impact | Same |
| 19 | Solution | Solution | Same |
| 20 | Affected Software/OS | Affected Software/OS | Same |
| 21 | Vulnerability Insight | Vulnerability Insight | Same |
| 22 | Vulnerability Detection Method | Vulnerability Detection Method | Same |
| 23 | Product Detection Result | Product Detection Result | Same |
| 24 | BIDs | BIDs | Same |
| 25 | CERTs | CERTs | Same |
| 26 | Other References | Other References | Same |

### Export XML:

1. Same process but select "XML" format
2. This produces the full GMP report XML, same schema as detailedresults.xml

### For ScottyScan -Validate Mode:

ScottyScan expects a simplified CSV with this schema:
  Status,ip,hostname,port,protocol,cvss,severity,qod,nvt_name

You will need to transform the GCE CSV export to match. A simple PowerShell
script can do this:

    Import-Csv detailedresults_gce.csv |
      Select-Object @{N='Status';E={'Queued'}},
                    @{N='ip';E={$_.IP}},
                    @{N='hostname';E={$_.Hostname}},
                    @{N='port';E={$_.Port}},
                    @{N='protocol';E={$_.'Port Protocol'}},
                    @{N='cvss';E={$_.CVSS}},
                    @{N='severity';E={$_.Severity}},
                    @{N='qod';E={$_.QoD}},
                    @{N='nvt_name';E={$_.'NVT Name'}} |
      Export-Csv scottyscan_input.csv -NoTypeInformation

---

## 11. RESULT COMPARISON CHECKLIST

After your first GCE scan completes, compare against the legacy results
to verify equivalent coverage.

### Findings that MUST appear if configuration is correct:

These are high-confidence indicators that the scan is working properly:

AUTHENTICATED SCANNING VERIFICATION:
- [ ] "Authenticated Scan / LSC Info Consolidation (Windows SMB Login)"
      should appear for Windows hosts (legacy: 60 hosts)
- [ ] "7zip Detection (Windows SMB Login)" should detect 7-Zip versions
      (legacy: 46 findings across 43 hosts, version 9.20)
- [ ] "ASP.NET Core/.NET Core SDK Detection (Windows SMB Login)" should
      detect .NET versions (legacy: 45 findings across 19 hosts)
- [ ] "BIOS and Hardware Information Detection (Windows SMB Login)"
      should report Dell hardware info (legacy: 48 findings)

If these are MISSING, your SMB credentials are not working. Check:
- Credential username/password
- Remote Registry service status on targets
- Firewall rules (TCP 445 from scanner to targets)
- DNS resolution (scanner must resolve the AD domain)

NETWORK VULNERABILITY VERIFICATION:
- [ ] "Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS,
      D(HE)ater)" (legacy: 45 findings across 43 hosts)
- [ ] "Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH,
      D(HE)ater)" (legacy: 39 findings across 37 hosts)
- [ ] "Deprecated SSH-1 Protocol Detection" (legacy: 3 hosts)
- [ ] "Dell DRAC / iDRAC Default Credentials (HTTP)" on 192.168.101.208
      (legacy: root/calvin confirmed)

SOFTWARE VERSION VULNERABILITY VERIFICATION:
- [ ] Adobe Flash Player EOL findings (legacy: 8 hosts)
- [ ] Apache Tomcat vulnerabilities (legacy: 20+ unique NVTs)
- [ ] .NET Core vulnerabilities (legacy: 30+ unique NVTs)
- [ ] 7-Zip vulnerabilities (legacy: 9 unique NVTs)

### Expected differences:

- NEW findings: GCE with a newer feed will have VTs published after
  November 2025 that the legacy scanner did not have
- MISSING findings: Some hosts may have been patched/decommissioned
  since November 2025
- Finding counts: May differ slightly due to feed version differences
  and scan timing
- CVE counts: The newer feed may map additional CVEs to existing NVTs

---

## 12. KNOWN GAPS BETWEEN LEGACY AND COMMUNITY EDITION

### What GCE Can Do That the Legacy Platform Did:

Everything. The legacy platform used the Greenbone Community Feed
(all NVT OIDs confirmed as 1.3.6.1.4.1.25623.x), which is the SAME
feed available in GCE. Specific capabilities confirmed as available:

- Authenticated Windows scanning via SMB
- Active exploitation checks (Apache Struts S2-045, etc.)
- Default credential testing (Dell iDRAC, etc.)
- SSH protocol analysis (D(HE)ater, SSH-1)
- TLS cipher analysis (D(HE)ater)
- Software version detection via registry
- CVSS scoring with QoD metrics
- CSV and XML export

### What GCE Does NOT Do That the Legacy Platform Did:

1. NMAP INTEGRATION: The legacy platform ran Nmap automatically as a
   discovery phase. GCE has its own built-in port scanner (Boreas) but
   does NOT use Nmap. The built-in scanner is adequate but may differ
   slightly in what it discovers.

   Workaround: Run Nmap separately before the GCE scan if you want
   identical discovery results. You can import Nmap results as a host
   list in the GCE target definition.

2. AUTOMATED REPORTING: The legacy platform (vPenTest) auto-generated
   executive summary PDFs with trend charts, remediation roadmaps, and
   branded formatting. GCE produces basic PDF/HTML reports.

   Workaround: Use a reporting tool like Faraday, DefectDojo, or build
   custom reports from the CSV/XML exports.

3. MONTH-OVER-MONTH TRENDING: The legacy platform tracked finding counts
   across monthly scans (the executive summary showed a trend chart from
   June-November 2025). GCE does not have built-in trending.

   Workaround: Export CSV after each monthly scan and build trending in
   Excel/PowerBI, or use DefectDojo which tracks findings over time.

4. ACTIVE EXPLOITATION (METASPLOIT): The legacy platform had Metasploit
   installed (.msf4 directory found in the evidence). GCE does not include
   Metasploit. However, the legacy pentest_findings.csv was empty,
   meaning no manual exploitation was actually performed -- so this is
   not a practical gap for this engagement.

### What GCE Can Do That the Legacy Platform Did NOT:

1. SSH AUTHENTICATED SCANNING: The legacy scan only authenticated on
   Windows via SMB. GCE can also authenticate on Linux via SSH, which
   would catch locally-installed package vulnerabilities that the legacy
   scan missed entirely on Linux hosts.

2. FULL PORT RANGE: The legacy scan only covered 499 TCP ports. GCE can
   scan all 65535 TCP ports, potentially finding services the legacy
   scanner missed.

3. COMPLIANCE SCANNING: GCE includes CIS benchmark and policy audit
   capabilities that the legacy scan did not use.

---

## 13. SCHEDULING MONTHLY SCANS

The legacy engagement was a monthly scan. Set up a recurring schedule:

1. Navigate to Configuration > Schedules
2. Click the star icon (New Schedule)
3. Fill in:

   Name: Monthly Internal Scan
   First Run: [Set to the 15th of next month, 00:00 local time]
     (The legacy scan ran on the 15th at midnight PT)
   Period: 1 month
   Duration: 0 (no limit -- let it run to completion)
   Timezone: America/Los_Angeles (or your local timezone)

4. Click Create
5. Edit the scan task (Scans > Tasks > edit) and assign this schedule

### Maintenance Window Considerations:

The legacy scan ran on a Saturday (November 15, 2025 was a Saturday).
Schedule your monthly scans during a maintenance window:
- Weekend nights are ideal (minimal user activity)
- Authenticated scanning generates SMB traffic to every Windows host
- Active checks (like Struts S2-045) could trigger IDS/IPS alerts
- Inform the SOC/NOC team that scanning will occur

---

## 14. APPENDIX A: FULL TCP PORT LIST FROM LEGACY SCANNER

(See Section 7 for the complete comma-separated list of 499 TCP ports
and 6 UDP ports extracted from the Nmap command line.)

Total: 499 TCP ports + 6 UDP ports = 505 port probes per host

Key port categories covered:
- Standard services: 21-25, 53, 80, 110, 143, 443, 993, 995
- Windows infrastructure: 88, 135, 139, 389, 445, 636, 3268-3269,
  3389, 5985, 5986, 47001, 49152-49176
- Database: 1433-1434, 3050, 3306, 5432-5433
- Pervasive/Sage: 1583, 3351
- Web servers: 8080-8090, 8443, 9090, 9443
- Monitoring: 5666 (Nagios), 6556 (Checkmk), 9100 (Prometheus),
  10050-10051 (Zabbix)
- VMware: 902, 5989, 8000, 8300
- Dell management: 1311 (OMSA), 623 (IPMI/iDRAC)
- ICS/SCADA: 502, 4840, 34571-34573

---

## 15. APPENDIX B: LEGACY SCAN STATISTICS FOR COMPARISON

Use these numbers to validate your GCE scan is producing comparable output.

### Scope
- Target CIDRs: 192.168.100.0/23 + 192.168.199.0/24
- Total addressable IPs: 768
- Hosts with open ports: 104
- Hosts scanned by OpenVAS: 102

### Results Summary
- Total findings: 1000 (including Log/Informational)
- Actionable findings (non-Log): 431
  - High: 295 (29.5%)
  - Medium: 131 (13.1%)
  - Low: 5 (0.5%)
  - Log: 569 (56.9%)
- Unique NVT checks run: 144
- Unique CVEs referenced: 154
- CVE year range: 2001-2025
- Average CVSS (non-Log): 7.12

### Scan Duration
- Nmap discovery: 3.5 minutes
- OpenVAS vulnerability scan: 9.5 hours
- Total wall clock: ~10 hours

### Top Findings by Volume
1. D(HE)ater TLS: 45 findings across 43 hosts
2. D(HE)ater SSH: 39 findings across 37 hosts
3. .NET Core vulnerabilities: 35+ findings across 12 hosts
4. Apache Tomcat: 20+ unique NVTs across 2 hosts (ilas1as14, ilas1as09)
5. 7-Zip: 9 unique NVTs across 3 hosts
6. Adobe Flash EOL: 8 hosts
7. Dell iDRAC default creds: 1 host (192.168.101.208)
8. Deprecated SSH-1: 3 hosts
9. Apache Struts S2-045 RCE: 1 host (confirmed exploitable)

### Authentication Evidence
- 60 hosts with SMB authenticated scan confirmation
- 47 hosts with BIOS/hardware info via SMB
- 43 hosts with 7-Zip detected via SMB
- 19 hosts with .NET Core detected via SMB
- 0 hosts with SSH authenticated scanning (gap in legacy)
