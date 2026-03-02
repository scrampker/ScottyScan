# 09 -- OpenVAS / Greenbone Integration

This chapter covers everything related to OpenVAS (Greenbone) integration with ScottyScan, including the Validate mode CSV format, the legacy scanner analysis that informed ScottyScan's design, and a complete guide to deploying Greenbone Community Edition as a replacement for the legacy vPenTest platform.

---

## Table of Contents

1. [OpenVAS CSV Format (ScottyScan Input)](#1-openvas-csv-format-scottyscan-input)
2. [Validate Mode Workflow](#2-validate-mode-workflow)
3. [Plugin-to-NVT Matching](#3-plugin-to-nvt-matching)
4. [Validated CSV Output Format](#4-validated-csv-output-format)
5. [OpenVAS Detailed Export Format (26-Column CSV)](#5-openvas-detailed-export-format-26-column-csv)
6. [Transforming GCE Export for ScottyScan](#6-transforming-gce-export-for-scottyscan)
7. [Quality of Detection (QoD) Reference](#7-quality-of-detection-qod-reference)
8. [NVT OID Structure and Feed Identity](#8-nvt-oid-structure-and-feed-identity)
9. [Greenbone Community Edition Setup](#9-greenbone-community-edition-setup)
10. [Legacy Scanner Analysis](#10-legacy-scanner-analysis)
11. [Coverage Comparison](#11-coverage-comparison)

---

## 1. OpenVAS CSV Format (ScottyScan Input)

ScottyScan's `-Validate` mode consumes CSV files with this 9-column schema:

```
Status,ip,hostname,port,protocol,cvss,severity,qod,nvt_name
```

### Column definitions

| # | Column | Type | Description |
|---|--------|------|-------------|
| 1 | Status | string | Finding status: `Queued`, `Pending Review`, `Remediated`, `Confirmed Vulnerable` |
| 2 | ip | string | Target IP address (may be zero-padded in OpenVAS exports) |
| 3 | hostname | string | Resolved hostname |
| 4 | port | integer | TCP/UDP port number |
| 5 | protocol | string | `tcp` or `udp` |
| 6 | cvss | decimal | CVSS score (0.0 -- 10.0) |
| 7 | severity | string | `Log`, `Low`, `Medium`, `High` |
| 8 | qod | integer | Quality of Detection (1 -- 100) |
| 9 | nvt_name | string | Vulnerability test name (may contain commas) |

### Example row

```
Queued,192.168.100.164,ilas1win1002.infowerks.com,3389,tcp,7.5,High,30,Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)
```

### Parsing rules

The CSV parser (`Import-OpenVASCSV` in ScottyScan.ps1) handles the following edge cases:

- **Commas in nvt_name**: The `nvt_name` field is the LAST column and can contain commas. The D(HE)ater entries are a real-world example: `Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)`. The parser splits each line on commas, takes the first 8 fields as columns 1--8, and joins everything from field 9 onward back together as the `nvt_name`. This is why `Import-Csv` cannot be used for this file -- it would split `nvt_name` at the embedded comma and corrupt the data.

- **Zero-padded IPs**: OpenVAS sometimes exports IPs with zero-padded octets (e.g., `192.168.101.001` instead of `192.168.101.1`). ScottyScan normalizes all IPs by splitting on `.` and casting each octet to `[int]` before rejoining, which strips any leading zeros.

- **Blank lines**: Empty or whitespace-only lines are silently skipped.

- **Header row**: The first line is treated as a header and skipped. The parser does not validate header names.

### Source reference

The parser implementation is the `Import-OpenVASCSV` function (approximately line 3736 in ScottyScan.ps1):

```powershell
$parts = $line -split ','
if ($parts.Count -ge 9) {
    [void]$rows.Add([ordered]@{
        Status   = $parts[0]
        ip       = $parts[1]
        hostname = $parts[2]
        port     = $parts[3]
        protocol = $parts[4]
        cvss     = $parts[5]
        severity = $parts[6]
        qod      = $parts[7]
        nvt_name = ($parts[8..($parts.Count - 1)] -join ',')
    })
}
```

---

## 2. Validate Mode Workflow

Validate mode (`-Validate`) reads an OpenVAS CSV, matches each finding to a registered plugin, re-tests the specific host+port+vulnerability combination, and produces a validated CSV with updated status values.

### Execution phases

**Phase 1 -- Load and Parse**

1. Parse the OpenVAS CSV using `Import-OpenVASCSV`.
2. Normalize all IPs (strip zero-padding).
3. Extract unique IPs from the CSV.
4. Run host discovery (port scanning) against all unique IPs to determine which are alive and what ports are open.
5. Run OS fingerprinting on discovered hosts.

**Phase 2 -- Match and Validate**

6. For each finding row, call `Find-Validator` to match the `nvt_name` against all loaded plugins' `NVTPattern` regex.
7. Filter matches to only include plugins that were selected by the user (in the TUI plugin selection step or via CLI).
8. Deduplicate test targets -- if the same IP:port:plugin combination appears multiple times (e.g., same vulnerability reported on multiple scans), it is tested only once.
9. Execute tests via `Invoke-PluginScan` using the same RunspacePool engine as Scan and List modes. Each plugin runs its `TestBlock` against the specific host+port from the OpenVAS finding.

**Phase 3 -- Output**

10. Build a result lookup keyed by `IP:Port`.
11. Produce the validated CSV (`Validated_<timestamp>.csv`) with the original rows plus four appended validation columns.
12. Update the `Status` column based on test results:
    - `Vulnerable` test result sets Status to `Confirmed Vulnerable`
    - `Remediated` test result sets Status to `Remediated`
    - Original status is preserved if no plugin matched the finding
13. Run any additional selected output generators (Master CSV, Summary Report, etc.).

### CLI examples

Interactive (TUI):
```powershell
.\ScottyScan.ps1 -Validate
# Select plugins, outputs, and CSV file through the menu system
```

Non-interactive:
```powershell
.\ScottyScan.ps1 -Validate -InputCSV .\openvas_findings.csv -NoMenu
```

### Key implementation detail

Validate mode performs host discovery against every unique IP in the CSV, even though the CSV already contains port information. This is intentional -- it confirms which hosts are currently reachable and populates the `OpenPorts` list for each host, which is used by the scan engine's port intersection logic. A host that appeared in the OpenVAS export but is now offline will be discovered as unreachable, and its findings will retain their original status in the output.

---

## 3. Plugin-to-NVT Matching

Each ScottyScan plugin registers an `NVTPattern` -- a regular expression matched against the `nvt_name` column of the OpenVAS CSV. The `Find-Validator` function iterates through all registered validators sorted by priority and returns the first match.

### Current plugin NVT patterns

| Plugin | NVTPattern Regex | Matches These NVT Names |
|--------|-----------------|------------------------|
| DHEater-TLS | `Diffie-Hellman Ephemeral.*SSL/TLS\|D\(HE\)ater.*SSL/TLS` | Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater) |
| DHEater-SSH | `Diffie-Hellman Ephemeral.*SSH\|D\(HE\)ater.*SSH` | Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSH, D(HE)ater) |
| SSH1-Deprecated | `Deprecated SSH-1 Protocol` | Deprecated SSH-1 Protocol Detection |
| 7Zip-Version | `7-Zip.*Vulnerabilit\|7-Zip.*Mark-of-the-Web` | 7-Zip Mark-of-the-Web Bypass Vulnerability, 7-Zip Multiple Vulnerabilities, etc. |

### Matching logic

The `Find-Validator` function (approximately line 1586 in ScottyScan.ps1) performs three checks in order:

1. **NVTPattern match**: The `nvt_name` must match the plugin's regex pattern (`-match` operator).
2. **PortFilter match**: If the plugin defines a `PortFilter`, the finding's port must match it.
3. **ProtoFilter match**: If the plugin defines a `ProtoFilter`, the finding's protocol must match it.

Validators are sorted by `Priority` (lower number = higher priority). The first validator that passes all three checks is returned. This means if two plugins could match the same NVT name, the one with the lower priority number wins.

### Unmatched findings

Findings whose `nvt_name` does not match any registered plugin's `NVTPattern` are counted as unmatched. Their original row is preserved in the validated CSV output with no changes to the Status column and empty validation columns. The count of unmatched findings is logged for visibility.

In the legacy scan data, 144 unique NVT names were found, but only 4 of those are covered by the current plugin set (DHEater-TLS, DHEater-SSH, SSH-1, and 7-Zip variants). Findings for .NET Core, Apache Tomcat, Adobe Flash, CUPS, Dell iDRAC, and all other NVTs pass through unvalidated. Writing additional plugins to cover more NVTs increases the validation coverage.

---

## 4. Validated CSV Output Format

The validated CSV (`Validated_<timestamp>.csv`) contains the original 9 columns plus 4 appended validation columns:

```
Status,ip,hostname,port,protocol,cvss,severity,qod,nvt_name,Validation_Result,Validation_Detail,Validation_Plugin,Validation_Timestamp
```

### Appended columns

| Column | Description |
|--------|-------------|
| Validation_Result | `Vulnerable`, `Remediated`, `Unreachable`, `Error`, `Inconclusive`, or empty (if no plugin matched) |
| Validation_Detail | Free-text detail from the plugin's TestBlock (e.g., cipher suite names, SSH KEX algorithms found) |
| Validation_Plugin | Name of the plugin that tested this finding (e.g., `DHEater-TLS`) |
| Validation_Timestamp | ISO-style timestamp of when validation was performed |

### Status column updates

When the `-UpdateStatus` flag is active (which it always is in Validate mode), the original `Status` column is updated:

| Validation_Result | New Status Value |
|-------------------|-----------------|
| Vulnerable | Confirmed Vulnerable |
| Remediated | Remediated |
| Unreachable | (original preserved) |
| Error | (original preserved) |
| Inconclusive | (original preserved) |
| (no match) | (original preserved) |

This means the output CSV can be used as a direct replacement for the input CSV in a tracking workflow -- previously-queued findings now show their validated status.

---

## 5. OpenVAS Detailed Export Format (26-Column CSV)

The full OpenVAS/Greenbone CSV export (as produced by Greenbone Security Assistant) contains 26 columns. This is the native export format, distinct from ScottyScan's simplified 9-column input format.

| # | Column | Description |
|---|--------|-------------|
| 1 | IP | Target IP address |
| 2 | Hostname | Resolved hostname |
| 3 | Port | Port number |
| 4 | Port Protocol | `tcp` or `udp` |
| 5 | CVSS | CVSS score (0.0 -- 10.0) |
| 6 | Severity | `Log`, `Low`, `Medium`, `High` (no `Critical` in Community Feed -- the legacy vendor report used its own severity mapping) |
| 7 | QoD | Quality of Detection (1 -- 100) |
| 8 | Solution Type | `VendorFix`, `Mitigation`, `WillNotFix`, `Workaround`, `NoneAvailable`, or empty |
| 9 | NVT Name | Vulnerability test name |
| 10 | Summary | Description of what the check does |
| 11 | Specific Result | Actual findings on this specific host (e.g., detected version, matched banner) |
| 12 | NVT OID | Greenbone OID (e.g., `1.3.6.1.4.1.25623.1.0.108440`) |
| 13 | CVEs | Associated CVE IDs (comma-separated if multiple) |
| 14 | Task ID | UUID of the scan task |
| 15 | Task Name | Human-readable name of the scan task |
| 16 | Timestamp | ISO 8601 scan timestamp |
| 17 | Result ID | UUID of this specific result entry |
| 18 | Impact | Description of the vulnerability's impact |
| 19 | Solution | Remediation guidance text |
| 20 | Affected Software/OS | Affected product identifiers |
| 21 | Vulnerability Insight | Technical details about the vulnerability mechanism |
| 22 | Vulnerability Detection Method | How the check determines vulnerability status |
| 23 | Product Detection Result | CPE string and version detection info |
| 24 | BIDs | Bugtraq IDs |
| 25 | CERTs | CERT advisory references (DFN-CERT, CERT-Bund, etc.) |
| 26 | Other References | Additional reference URLs |

This 26-column format was confirmed by parsing the 1000-record `detailedresults.csv` export from the November 2025 legacy assessment. See `openvas_legacy_research/csv_analysis.md` for the full breakdown.

---

## 6. Transforming GCE Export for ScottyScan

Greenbone Community Edition exports the 26-column CSV. ScottyScan expects the simplified 9-column format. Use this PowerShell one-liner to transform the export:

```powershell
Import-Csv detailedresults.csv |
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
```

### Notes on the transformation

- **Status column**: All rows are set to `Queued` since these are fresh findings that have not yet been validated.
- **Import-Csv is safe here**: The 26-column GCE export uses proper CSV quoting for fields containing commas, so `Import-Csv` handles it correctly. It is only the simplified 9-column format (where `nvt_name` is the last column and may not be quoted) where `Import-Csv` breaks.
- **Filtering before import**: You may want to filter out `Log` severity findings before transformation, since they are informational detections (software version found, HTTP methods enumerated, etc.) rather than actionable vulnerabilities. Add a `Where-Object { $_.Severity -ne 'Log' }` before `Select-Object` to do this.
- **QoD filtering**: The legacy scan included QoD values as low as 1 (general notes) and 30 (remote probes). Consider filtering to `QoD -ge 70` for higher-confidence findings only, or keep everything and let ScottyScan validate regardless of QoD.

### Filtering example

To produce a ScottyScan input CSV containing only High and Medium findings with QoD of 70 or above:

```powershell
Import-Csv detailedresults.csv |
  Where-Object { $_.Severity -in @('High','Medium') -and [int]$_.QoD -ge 70 } |
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
```

---

## 7. Quality of Detection (QoD) Reference

OpenVAS assigns a Quality of Detection score to each finding, indicating how confident the scanner is in the result. Higher QoD means higher confidence.

| QoD | Level | Description |
|-----|-------|-------------|
| 100 | exploit | Confirmed by actual exploitation |
| 99 | remote_vul | Remote vulnerability check (active test) |
| 98 | remote_app | Remote application detection |
| 97 | package | Package version check (authenticated, e.g., SMB Login) |
| 95 | registry | Registry-based detection |
| 80 | remote_banner | Service banner matching (e.g., SSH version string) |
| 70 | remote_banner_unreliable | Banner matching with known unreliability |
| 50 | remote_analysis | Remote analysis heuristic |
| 30 | remote_probe | Remote probe with low confidence |
| 1 | general_note | General informational note |

### QoD distribution from the legacy scan

The November 2025 legacy assessment (1000 findings) had this QoD distribution:

| QoD | Count | Percent | Implication |
|-----|------:|--------:|-------------|
| 97 | 408 | 40.8% | Authenticated SMB checks (Windows software versions) |
| 80 | 393 | 39.3% | Banner-based checks (SSH, TLS, HTTP) |
| 70 | 100 | 10.0% | Unreliable banner checks |
| 30 | 93 | 9.3% | Remote probes (D(HE)ater findings) |
| 99 | 3 | 0.3% | Active vulnerability checks (Apache Struts S2-045) |
| 1 | 3 | 0.3% | General notes |

The default Greenbone Community Edition QoD filter threshold is 70%, which would hide the QoD 30 findings (93 results, including all D(HE)ater entries) and QoD 1 findings. To see all findings in the GCE web UI, change the results filter from `min_qod=70` to `min_qod=1`.

### QoD and ScottyScan validation

ScottyScan does not filter by QoD -- all findings in the input CSV are candidates for validation regardless of their QoD value. The QoD column is preserved in the validated output CSV for reference. The rationale is that ScottyScan's plugin tests perform their own active verification (sending TLS ClientHello, parsing SSH KEX_INIT, etc.), which inherently produces a high-confidence result independent of the original QoD.

---

## 8. NVT OID Structure and Feed Identity

All Greenbone Community Feed NVTs use the OID prefix `1.3.6.1.4.1.25623`. This prefix is registered to Greenbone AG in the IANA Private Enterprise Numbers registry.

### Why this matters

The legacy vulnerability scanner (Vonahi Security vPenTest) used the same Greenbone Community Feed. Every single NVT OID in the legacy scan's 1000-record export began with `1.3.6.1.4.1.25623`. This confirms:

1. **Identical vulnerability tests**: The Community Edition has access to the same NVTs that produced the legacy findings. Switching from vPenTest to a self-hosted GCE instance does not reduce vulnerability detection coverage for the NVT families that were exercised.

2. **Feed update timing**: The Community Feed may lag the commercial Greenbone Enterprise Feed by 1--2 weeks for newly published VTs. For monthly scan cadences, this gap is negligible.

3. **OID stability**: NVT OIDs are permanent identifiers. An NVT's OID does not change when its check logic is updated, which means historical findings can be tracked across feed versions.

### Sample OIDs from the legacy scan

```
1.3.6.1.4.1.25623.1.0.108440   -- D(HE)ater TLS
1.3.6.1.4.1.25623.1.0.108442   -- D(HE)ater SSH
1.3.6.1.4.1.25623.1.0.108975   -- Deprecated SSH-1 Protocol Detection
1.3.6.1.4.1.25623.1.0.107013   -- 7-Zip vulnerability checks
```

The full list of 145 unique OIDs is documented in `openvas_legacy_research/csv_analysis.md` (Section 9).

---

## 9. Greenbone Community Edition Setup

This section summarizes the key points from the full setup guide at `openvas_legacy_research/Greenbone_CE_Setup_Guide.md`.

### Deployment method

Docker Compose is the officially supported deployment method. The stack includes: gvmd (Greenbone Vulnerability Manager), openvas-scanner, gsad (web UI), pg-gvm (PostgreSQL), ospd-openvas (scanner bridge), notus-scanner (local security checks), and an MQTT broker.

```bash
mkdir -p /opt/greenbone && cd /opt/greenbone
curl -fsSL https://greenbone.github.io/docs/latest/_static/docker-compose.yml \
  -o docker-compose.yml
docker compose up -d
```

Default web UI access: `https://<scanner-ip>:9392` with username `admin` and password `admin` (change immediately).

### Hardware requirements

- Minimum: 4 CPU cores, 8 GB RAM, 40 GB disk
- Recommended for 100+ host scans: 8 CPU cores, 16 GB RAM
- The VT feed alone is 10+ GB on disk

### Initial feed sync (critical)

The VT feed is what makes OpenVAS useful. Without it, the scanner has zero vulnerability checks. The initial sync takes 30--60 minutes and must complete before scanning.

Monitor progress:
```bash
docker compose logs -f greenbone-feed-sync
```

Verify completion in the GSA web UI under Administration > Feed Status. All feeds (NVT, SCAP, CERT, GVMD_DATA) should show status "Current" with a recent timestamp. Do not create scan tasks until the NVT feed shows "Current".

Set up daily feed updates:
```bash
# Cron entry for Docker deployment
0 3 * * * cd /opt/greenbone && docker compose exec -T greenbone-feed-sync greenbone-feed-sync
```

### Scan configuration

Use the built-in "Full and fast" scan configuration. It matches the legacy scan behavior:
- Runs all safe NVT families (no destructive checks)
- Includes version detection, service enumeration, and vulnerability checks
- Performs authenticated checks when credentials are provided
- Includes active exploitation checks (e.g., Apache Struts S2-045)
- Uses a QoD threshold of 70% by default (adjustable)

### Credential configuration

**SMB credentials (required for Windows hosts)**:

The legacy scan performed authenticated Windows scanning via SMB login. Without SMB credentials, approximately 40% of findings will be missed -- all "Windows SMB Login" detections for 7-Zip, .NET Core, Adobe Flash, Adobe Acrobat, BIOS/hardware info, and other locally-installed software.

Create an SMB credential in GCE with:
- Type: Username + Password
- Login: `DOMAIN\admin-username` (domain admin or local admin)
- Assign to the target definition under "Credentials for authenticated checks"

Requirements on target hosts:
- Local admin or domain admin privileges for the credential account
- File and Printer Sharing enabled (TCP 445 reachable)
- Remote Registry service running (or set to Manual and startable remotely)
- Windows Firewall allowing SMB (TCP 445) and WMI (TCP 135 + dynamic RPC) from the scanner IP

**SSH credentials (optional, improves Linux coverage)**:

The legacy scan did NOT perform authenticated scanning on Linux hosts. This is a gap that GCE can close. Adding SSH credentials enables package-level vulnerability detection on Linux, similar to what SMB Login provides for Windows.

### Port list options

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| All TCP + Nmap top 100 UDP | All 65535 TCP ports + top 100 UDP | Maximum coverage | Longer scan time (12--18 hours) |
| Custom 499 TCP + 6 UDP | Exact match of legacy port list | Identical scope, faster (~9.5 hours) | May miss services on unlisted ports |
| All IANA Assigned TCP | ~5000 IANA-registered ports | Good balance | Middle ground on both |

Recommendation: Start with "All TCP + Nmap top 100 UDP" for the first scan to establish a comprehensive baseline. Switch to the custom port list for ongoing monthly scans if duration is a concern.

The full 499 TCP port list extracted from the legacy Nmap command is documented in `openvas_legacy_research/Greenbone_CE_Setup_Guide.md` (Section 7).

### Monthly scheduling

The legacy engagement ran monthly scans (confirmed by the executive summary trend chart showing data from June through November 2025). Configure a schedule in GCE:

1. Navigate to Configuration > Schedules
2. Create a new schedule: monthly recurrence, starting on the desired date
3. Assign the schedule to the scan task

Schedule scans during maintenance windows (weekends preferred). Authenticated scanning generates SMB traffic to every Windows host, and active checks can trigger IDS/IPS alerts.

---

## 10. Legacy Scanner Analysis

The `openvas_legacy_research/` directory contains the complete analysis of the November 2025 legacy vulnerability assessment. This analysis informed ScottyScan's plugin design and the GCE replication strategy.

### Research files

| File | Description |
|------|-------------|
| `csv_analysis.md` | Full 26-column schema breakdown, severity distribution, NVT inventory, IP/port analysis, CVE catalog, QoD distribution, authentication evidence, and scan timing from the 1000-record `detailedresults.csv` |
| `nmap_analysis.md` | Nmap command reconstruction from `port_scans.nmap` and `port_scans.gnmap`, 499 TCP + 6 UDP port list extraction, host count summary, service identification, MAC vendor analysis |
| `pdf_analysis.md` | Platform identification (Vonahi Security vPenTest), scan methodology, authentication analysis, finding counts by severity, remediation priority guidance from the executive summary and vulnerability report PDFs |
| `Greenbone_CE_Setup_Guide.md` | Step-by-step guide to deploying GCE with the same configuration as the legacy scanner, including target definition, credential setup, port list, scan config, result export, and comparison checklist |

### Platform identification

- **Vendor**: Vonahi Security (vpentest.io)
- **Product**: vPenTest -- automated internal/external network penetration testing platform
- **Underlying scanner**: OpenVAS with Greenbone Community Feed (VT version 23.20.1)
- **Discovery tool**: Nmap 7.95
- **Scanner host**: Linux Docker-based VM at 192.168.101.99 (ens160 interface)
- **Additional tooling**: Metasploit Framework was installed but no exploitation was performed

### Scan methodology

The legacy platform used a two-phase approach:

**Phase 1 -- Discovery (Nmap, ~3.5 minutes)**:
- Nmap SYN + UDP scan (`-Pn -T3 -n -sSU`)
- 499 specific TCP ports + 6 UDP ports (not a full 65535 sweep)
- 768 target IPs across three subnets
- 346 hosts reported "up" (104 with confirmed open ports)
- No service version detection (`-sV`), no OS fingerprinting (`-O`), no NSE scripts

**Phase 2 -- Vulnerability Assessment (OpenVAS, ~9.5 hours)**:
- Authenticated Windows scanning via SMB login
- Unauthenticated network scanning on Linux and appliance hosts
- Active exploitation checks included (Apache Struts S2-045 confirmed code execution)
- 102 hosts scanned, 1000 total findings, 144 unique NVTs, 154 unique CVEs

### Key findings from the legacy scan data

| Metric | Value |
|--------|-------|
| Total findings | 1000 |
| Actionable findings (non-Log) | 431 |
| High severity | 295 (29.5%) |
| Medium severity | 131 (13.1%) |
| Low severity | 5 (0.5%) |
| Log/Informational | 569 (56.9%) |
| Unique NVTs | 144 |
| Unique CVEs | 154 (spanning 2001--2025) |
| Average CVSS (non-Log) | 7.12 |
| Unique IPs | 102 |
| Unique port/protocol pairs | 43 |
| Scan duration | 9 hours 28 minutes |

### Top vulnerability categories by finding count

1. **D(HE)ater TLS** (CVE-2002-20001): 45 findings across 43 hosts on ports 3389, 443, 5432, 25, and others
2. **D(HE)ater SSH** (CVE-2002-20001): 39 findings across 37 hosts on ports 22 and 1022
3. **.NET Core vulnerabilities**: 35+ findings across 12 hosts (DoS, RCE, privilege escalation, information disclosure)
4. **Apache Tomcat vulnerabilities**: 20+ unique NVTs across 2 hosts (severely outdated versions 8.5.71 and 9.0.8)
5. **7-Zip vulnerabilities**: 9 unique NVTs across 3 hosts (version 9.20 from 2010 still deployed on 40+ hosts)
6. **Adobe Flash Player EOL**: 8 hosts (still installed, EOL since December 2020)
7. **Deprecated SSH-1 Protocol**: 3 hosts

### Authentication evidence

The legacy scan performed authenticated Windows scanning:
- 60 hosts confirmed with "Authenticated Scan / LSC Info Consolidation (Windows SMB Login)"
- 47 hosts with BIOS/hardware info via SMB
- 43 hosts with 7-Zip detected via SMB
- 19 hosts with .NET Core detected via SMB
- 0 hosts with SSH authenticated scanning (gap -- Linux hosts were unauthenticated only)

---

## 11. Coverage Comparison

### What GCE provides that the legacy platform also provided

Everything relevant to vulnerability detection. The legacy platform used the Greenbone Community Feed (all NVT OIDs confirmed), which is the same feed available in GCE. Specific capabilities confirmed as available in both:

- Authenticated Windows scanning via SMB
- Active exploitation checks (Apache Struts S2-045, etc.)
- Default credential testing (Dell iDRAC root/calvin, etc.)
- SSH protocol analysis (D(HE)ater, SSH-1)
- TLS cipher analysis (D(HE)ater)
- Software version detection via registry
- CVSS scoring with QoD metrics
- CSV and XML export

### What GCE does NOT provide that the legacy platform did

1. **Automated executive reporting**: vPenTest auto-generated branded PDFs with executive summaries, trend charts, and remediation roadmaps. GCE produces basic PDF/HTML reports. Workaround: use DefectDojo or build custom reports from CSV/XML exports.

2. **Month-over-month trending**: vPenTest tracked finding counts across monthly scans. GCE does not have built-in trending. Workaround: export CSV after each monthly scan and build trending in Excel or PowerBI.

3. **Integrated Nmap discovery**: vPenTest ran Nmap automatically as a discovery phase. GCE uses its own built-in port scanner (Boreas). Workaround: run Nmap separately if exact discovery parity is needed.

### What GCE provides that the legacy platform did NOT use

1. **SSH authenticated scanning**: Enables package-level vulnerability detection on Linux hosts. The legacy scan missed all locally-installed software vulnerabilities on Linux.

2. **Full port range scanning**: The legacy scan covered only 499 TCP ports. GCE can scan all 65535, potentially finding services the legacy scanner missed.

3. **Compliance scanning**: GCE includes CIS benchmark and policy audit capabilities.

### What ScottyScan adds beyond GCE

ScottyScan's Validate mode is specifically designed to re-test OpenVAS findings with independent verification:

- **Active protocol-level testing**: ScottyScan sends actual TLS ClientHello messages and parses SSH KEX_INIT responses, rather than relying on banner matching or version inference.
- **Targeted validation**: Instead of re-running the entire scan, Validate mode tests only the specific host+port+vulnerability combinations from the OpenVAS CSV.
- **Status tracking**: The validated CSV output provides a before/after record suitable for remediation tracking workflows.
- **Software version checking**: The integrated Software Version Check engine inventories installed software via Remote Registry, PSRemoting, and WMI, with configurable flag rules for version-based alerting.

### GCE scan result verification checklist

After running your first GCE scan, verify these indicators to confirm equivalent coverage with the legacy platform:

**Authenticated scanning is working if**:
- "Authenticated Scan / LSC Info Consolidation (Windows SMB Login)" appears for Windows hosts
- "7zip Detection (Windows SMB Login)" detects 7-Zip versions
- "BIOS and Hardware Information Detection (Windows SMB Login)" reports hardware info

**Network vulnerability scanning is working if**:
- D(HE)ater TLS and SSH findings appear on RDP/SSH hosts
- "Deprecated SSH-1 Protocol Detection" appears on known SSH-1 hosts

**If authenticated findings are missing**, check:
- SMB credential username, password, and domain format
- Remote Registry service status on target Windows hosts
- Firewall rules allowing TCP 445 and TCP 135 from the scanner
- DNS resolution from the scanner to the Active Directory domain
