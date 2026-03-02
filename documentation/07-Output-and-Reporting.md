# Output and Reporting

This chapter documents every output format ScottyScan produces, how the reporting system works, and how the logging subsystem captures diagnostic detail.

---

## Output Directory

All output goes to `output_reports/` by default. This directory is created automatically at runtime if it does not exist and is gitignored.

```
output_reports/
    ScottyScan_Master_20260206_143022.csv        Master CSV
    ScottyScan_Report_20260206_143022.txt         Summary report
    ScottyScan_DHEater-TLS_20260206_143022.csv    Per-plugin CSV (one per plugin)
    ScottyScan_DHEater-SSH_20260206_143022.csv
    ScottyScan_SSH1-Deprecated_20260206_143022.csv
    Discovery_20260206_143022.csv                 Discovery CSV
    Validated_20260206_143022.csv                 Validated CSV (Validate mode only)
    SoftwareInventory_ALL_20260206_143022.csv     Full software inventory
    FLAGGED_ALL_TARGETS_20260206_143022.csv       All flagged software targets
    FLAGGED_ALL_IPs_20260206_143022.txt           All flagged IPs
    FLAGGED_notepad_TARGETS_20260206_143022.csv   Per-rule flagged targets
    FLAGGED_notepad_IPs_20260206_143022.txt       Per-rule flagged IPs
    logs/
        ScottyScan_20260206_143022.log            Verbose run log
```

All filenames include a timestamp (`yyyyMMdd_HHmmss`) to ensure uniqueness across runs. The timestamp is set once at script initialization and used consistently across all files from the same run.

### Overriding the Output Directory

Use the `-OutputDir` CLI parameter to write output to a different location:

```powershell
.\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu -OutputDir "C:\Reports"
```

If the path is relative, it is resolved to an absolute path relative to the script directory (`$PSScriptRoot`), not the current working directory. This ensures Discovery CSV reuse works correctly regardless of where you invoke the script from.

In interactive mode, the output directory defaults to the value stored in `scottyscan.json` under `LastOutputDir` (initially `.\output_reports`).

---

## Output Types

Output types are selectable through the interactive TUI (Step 5: Output Options) or via the `-Outputs` CLI parameter. Four output types are available:

| TUI Label | Value | Default | Description |
|-----------|-------|---------|-------------|
| Master findings CSV | `MasterCSV` | Selected | All findings in one CSV |
| Executive summary report | `SummaryReport` | Selected | Plain-text report for CAB/exec review |
| Per-plugin result CSVs | `PerPluginCSV` | Selected | Separate CSV per plugin |
| Host discovery CSV | `DiscoveryCSV` | Selected | Live hosts with open ports, hostname, and OS |

All four are selected by default. In CLI mode, specify which outputs to generate:

```powershell
-Outputs "MasterCSV,SummaryReport,PerPluginCSV,DiscoveryCSV"
```

Software Version Check outputs are generated automatically when the Software Version Check feature is enabled and are not controlled by the Outputs parameter.

---

### Master CSV

**Function:** `Export-MasterCSV`
**Filename:** `ScottyScan_Master_<timestamp>.csv`
**Encoding:** UTF-8

The Master CSV is a single file combining all results from all plugins and the Software Version Check into one flat table. This is the primary data file for analysis, filtering, and import into other tools.

#### Columns

| Column | Description |
|--------|-------------|
| IP | Target IP address |
| Hostname | Resolved hostname (empty string if unavailable) |
| OS | Detected operating system (empty string if unavailable) |
| Port | TCP port tested |
| Plugin | Name of the plugin that produced this result |
| Result | Test outcome (see Result Values below) |
| Detail | Full description of the finding (may be lengthy; commas and quotes are CSV-escaped) |
| Timestamp | When the result was recorded (`yyyy-MM-dd HH:mm:ss`) |

#### Result Values

Every finding carries one of five result values:

| Value | Meaning |
|-------|---------|
| `Vulnerable` | The vulnerability was confirmed present on this host+port |
| `Remediated` | The host+port was tested and the vulnerability is not present (or has been fixed) |
| `Unreachable` | The TCP connection to the port could not be established (port closed, host down, or firewall blocking) |
| `Error` | The test encountered an unexpected error during execution |
| `Inconclusive` | The test completed but could not definitively determine vulnerable or remediated status |

#### CSV Escaping

The Detail field is quoted and double-quote-escaped when it contains commas, quotes, or newlines. This follows standard CSV conventions so the file can be opened in Excel, imported into databases, or parsed by any CSV library.

---

### Summary Report

**Function:** `Export-SummaryReport`
**Filename:** `ScottyScan_Report_<timestamp>.txt`
**Encoding:** UTF-8

The Summary Report is a human-readable plain-text file designed for quick review and email distribution. It is structured in sections:

#### Report Header

```
================================================================
  ScottyScan Report
  Generated: 2026-02-06 14:30:22
  Mode: List
  Version: 1.0.0
================================================================
```

#### Summary Section

Aggregate counts of all test results:

```
SUMMARY
-------
  Total tests run:       84
  Vulnerable:            12
  Remediated\Clean:      58
  Unreachable:           8
  Errors:                2
  Inconclusive:          4
```

#### By Plugin Section

Result breakdown grouped by plugin name:

```
BY PLUGIN
---------

  [DHEater-TLS]
    Vulnerable           6
    Remediated           18
    Unreachable          4

  [DHEater-SSH]
    Vulnerable           4
    Remediated           22

  [SSH1-Deprecated]
    Remediated           14
    Unreachable          4
    Inconclusive         4
```

#### Vulnerable Findings Detail

Every finding with `Result = Vulnerable`, listed with full detail:

```
================================================================
  VULNERABLE (action required)
================================================================
  192.168.100.17   esxi01.example.com (ESXi/VMware)
    port 22     [DHEater-SSH]
    5 DHE kex algorithms: diffie-hellman-group-exchange-sha256, ...
```

#### Unreachable Hosts

Hosts where ports could not be reached, with the affected port list:

```
================================================================
  UNREACHABLE
================================================================
  192.168.100.50   server05.example.com             ports: 22, 443
```

#### Remediated / Clean

Hosts and ports where the vulnerability was confirmed absent:

```
================================================================
  REMEDIATED / CLEAN
================================================================
  192.168.100.10   dc01.example.com                 port 3389   [DHEater-TLS]
```

---

### Per-Plugin CSVs

**Filename:** `ScottyScan_<PluginName>_<timestamp>.csv`
**Encoding:** UTF-8

One CSV file is generated per plugin that produced results. Each file uses the same column format as the Master CSV (IP, Hostname, OS, Port, Plugin, Result, Detail, Timestamp) but contains only that plugin's findings.

Per-plugin CSVs are produced by calling `Export-MasterCSV` once per plugin group, so the format is identical to the Master CSV.

Use case: route specific vulnerability findings to different remediation teams. For example, send the `DHEater-TLS` CSV to the team managing SSL/TLS configurations and the `7Zip-Version` CSV to the desktop deployment team.

---

### Discovery CSV

**Function:** `Export-DiscoveryCSV`
**Filename:** `Discovery_<timestamp>.csv`
**Encoding:** UTF-8

The Discovery CSV records the results of the host discovery and OS fingerprinting phases. It is generated in Scan mode and List mode (when not reusing a prior Discovery CSV).

#### Columns

| Column | Description |
|--------|-------------|
| IP | Target IP address |
| Hostname | Resolved hostname |
| OS | Detected operating system (from TTL, CIM/WMI, SSH banner, port heuristics) |
| TTL | ICMP TTL value observed during ping (used for OS family guessing) |
| OpenPorts | Semicolon-separated list of open TCP ports discovered on this host |

#### Example

```csv
IP,Hostname,OS,TTL,OpenPorts
192.168.100.10,dc01.example.com,Windows Server 2019,128,53;88;135;389;443;445;636;3268;3269;3389;5985
192.168.100.17,esxi01.example.com,ESXi/VMware,64,22;80;443;902
192.168.100.50,ubuntu01.example.com,Ubuntu 22.04,64,22;80;443
```

#### Reuse in Subsequent Runs

Discovery CSVs can be reused in subsequent runs to skip the time-consuming host discovery and port scanning phase. When you start a new Scan or List mode run, the TUI checks the output directory for existing `Discovery_*.csv` files and offers to reuse them:

- **Scan mode:** Offers "Scan previously-discovered systems" vs. "Enter new CIDRs to scan"
- **List mode:** Offers "Use previous discovery results" vs. "Select a host list file"

When a Discovery CSV is loaded, its hosts and open ports are imported directly and the tool proceeds to OS fingerprinting and plugin scanning. The output directory path is resolved to an absolute path at startup, so Discovery CSV reuse works regardless of what directory you run the script from.

In List mode, ScottyScan also auto-detects Discovery CSVs passed as the host file by checking whether the first line matches the header `IP,Hostname,OS,TTL,OpenPorts`.

---

### Validated CSV (Validate Mode Only)

**Function:** `Export-ValidateCSV`
**Filename:** `Validated_<timestamp>.csv`
**Encoding:** UTF-8

In Validate mode, ScottyScan always produces a Validated CSV regardless of the Outputs selection. This file is a copy of the original OpenVAS CSV with four validation columns appended.

#### Columns

The original OpenVAS columns are preserved:

| Column | Source |
|--------|--------|
| Status | Original status, updated if validation changes it |
| ip | Target IP |
| hostname | Target hostname |
| port | Target port |
| protocol | Protocol (tcp/udp) |
| cvss | CVSS score |
| severity | Severity level (High, Medium, Low) |
| qod | Quality of Detection score |
| nvt_name | NVT name (may contain commas) |

Four validation columns are appended:

| Column | Description |
|--------|-------------|
| Validation_Result | The result from ScottyScan's re-test (Vulnerable, Remediated, Unreachable, Error, Inconclusive) |
| Validation_Detail | Detailed description of the validation finding |
| Validation_Plugin | Which ScottyScan plugin was matched and used for validation |
| Validation_Timestamp | When the validation was performed |

#### Status Updates

When validation produces a result, the original `Status` column is updated:

- If the validation result is `Remediated`, the Status is changed to `Remediated`
- If the validation result is `Vulnerable`, the Status is changed to `Confirmed Vulnerable`
- Other validation results do not modify the original Status

---

### Software Version Check Outputs

These outputs are generated automatically when the Software Version Check feature is enabled. They are produced by the `Export-SoftwareOutputs` function and are not controlled by the Outputs parameter.

#### SoftwareInventory_ALL_\<timestamp\>.csv

Complete software inventory of all discovered software across all scanned Windows hosts, filtered by the effective filter patterns (either explicit `-SoftwareFilter` patterns or patterns derived from flag rules).

Columns: ComputerName, Name, Version, Publisher, InstallDate, InstallPath, Architecture, Source

The `Source` column indicates which enumeration method was used: RemoteRegistry, PSRemoting, or WMI.

#### FLAGGED_ALL_TARGETS_\<timestamp\>.csv

Master list of all flagged software entries across all hosts and all flag rules.

Columns: ComputerName, Hostname, SoftwareName, Version, Architecture, InstallPath, FlagRule, FlagPattern, FlagLabel, Status

The Status column is always `FLAGGED`.

#### FLAGGED_ALL_IPs_\<timestamp\>.txt

Plain text file with one IP address per line. Contains the unique set of IP addresses that had at least one flagged software finding. Useful for feeding into deployment tools (SCCM, PDQ, etc.) or firewall rules.

#### FLAGGED_\<pattern\>_TARGETS_\<timestamp\>.csv

Per-rule breakdown. One CSV is generated for each unique flag rule (pattern + version rule combination). The `<pattern>` in the filename is derived from the flag pattern with special characters removed (e.g., `*notepad*` becomes `notepad`).

Columns: ComputerName, Hostname, SoftwareName, Version, Architecture, InstallPath, FlagRule, FlagLabel

#### FLAGGED_\<pattern\>_IPs_\<timestamp\>.txt

Per-rule IP list. One text file per flag rule containing unique IP addresses that matched that specific rule. Same naming convention as the per-rule targets CSV.

---

## Logging System

### Write-Log Function

`Write-Log` is the central logging function used throughout ScottyScan. It provides dual output: writing to both the console and a persistent log file.

**Signature:**
```powershell
Write-Log [-Message] <string> [-Level <string>] [-Silent]
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Message` | (required) | The log message text |
| `-Level` | `"INFO"` | Log level: INFO, ERROR, WARN, OK, DEBUG |
| `-Silent` | Off | When set, writes to the log file only (suppresses console output) |

**Log Format:**
```
[2026-02-06 14:30:22] [INFO] 14 hosts loaded from targets.txt
[2026-02-06 14:30:23] [OK] Discovery complete: 12 hosts alive
[2026-02-06 14:30:24] [WARN] Host 192.168.100.99 -- no open ports found
[2026-02-06 14:30:25] [ERROR] Plugin 7Zip-Version failed on 192.168.100.10: Access denied
```

**Console Colors:**

| Level | Color |
|-------|-------|
| INFO | Gray |
| ERROR | Red |
| WARN | Yellow |
| OK | Green |
| DEBUG | DarkGray |

### Log File Location

Log files are written to `output_reports/logs/` with the filename pattern:

```
ScottyScan_<timestamp>.log
```

The log file is created at script initialization, before any scanning begins. The same timestamp used for output filenames is used for the log filename, so all files from a single run share the same timestamp.

### The -Silent Switch

The `-Silent` switch is critical for correct TUI rendering. When ScottyScan is drawing the fixed-position discovery progress display using `Write-LineAt`, any call to `Write-Host` (which `Write-Log` uses internally for console output) would corrupt the display by injecting lines and causing terminal scrolling.

**Rule:** Never call `Write-Host` or `Write-Log` without `-Silent` inside a `Write-LineAt` rendering loop. Use `Write-Log -Silent` for file-only logging during TUI sections.

### What Gets Logged

The log file captures comprehensive detail about every aspect of a scan run:

**Startup and Configuration:**
- Plugin loading: names, declared scan ports, NVT patterns
- Selected mode, plugins, output types
- Thread count, timeout, port scanning configuration
- Input file paths

**Host Discovery:**
- Every discovered host with its full list of open ports
- OS fingerprinting results
- Hosts that responded to ping but had no open ports
- Total host and port counts

**Plugin Scanning:**
- Every individual plugin test result with full, untruncated detail
- This includes the complete cipher suite lists, SSH algorithm enumerations, and version strings that may be truncated in console output

**Software Version Check:**
- Enumeration method used per host (Remote Registry, PSRemoting, WMI)
- Software counts per host
- Every flagged software finding with version and rule match
- Enumeration failures and fallback attempts

**Output:**
- Full paths to every output file generated
- Entry counts for each output file

**Other Events:**
- Early exit events (when the user presses E during discovery)
- Errors and exceptions with stack traces
- Discovery CSV reuse (when loading from a prior run)

---

## Output Generation Flow

### Scan and List Modes

Output generation follows this sequence:

1. **Discovery CSV** -- Generated at the end of the discovery phase (Phase 1), before plugin scanning begins. In Scan mode, it is always generated. In List mode, it is generated when hosts are loaded from a host list file (not when reusing a prior Discovery CSV).

2. **Software Version Check outputs** -- Generated at the end of Phase 2 (if Software Version Check was enabled). Produced by `Export-SoftwareOutputs`.

3. **Master CSV, Summary Report, Per-Plugin CSVs** -- Generated at the end of Phase 3 (or final phase) by the `Export-Results` dispatcher function, based on the Outputs selection.

### Validate Mode

1. **Validated CSV** -- Always generated, regardless of Outputs selection. Produced at the start of the output phase.

2. **Master CSV, Summary Report, Per-Plugin CSVs** -- Generated by `Export-Results` based on the Outputs selection, same as other modes.

### Export-Results Dispatcher

The `Export-Results` function is the central output dispatcher. It checks the `SelectedOutputs` array and calls the appropriate export function for each selected output type:

```
SelectedOutputs contains "MasterCSV"     --> Export-MasterCSV
SelectedOutputs contains "SummaryReport" --> Export-SummaryReport
SelectedOutputs contains "PerPluginCSV"  --> Export-MasterCSV (once per plugin group)
```

Discovery CSV generation is handled separately, outside `Export-Results`, because it occurs during the discovery phase rather than the final output phase.

---

## Next Steps

- **[08-Configuration.md](08-Configuration.md)** -- Full CLI parameter reference and config file schema
- **[06-Software-Version-Check.md](06-Software-Version-Check.md)** -- Flag rules, version comparison operators, enumeration methods
- **[09-OpenVAS-Integration.md](09-OpenVAS-Integration.md)** -- Validate mode specifics and the OpenVAS CSV format
