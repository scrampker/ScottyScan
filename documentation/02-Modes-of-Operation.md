# ScottyScan -- Modes of Operation

ScottyScan supports three operational modes, each designed for a different workflow. All three share a common plugin system, output pipeline, and configuration layer, but differ in how they identify target hosts and scope their work.

---

## Scan Mode (-Scan)

### Purpose

Full network discovery followed by vulnerability scanning. Use this when you need to sweep one or more subnets, discover every live host, identify open ports, fingerprint operating systems, and then run vulnerability plugins against what you find.

### Execution Flow

```
CIDR Input -> IP Expansion -> Ping + TCP Port Scan -> OS Fingerprint -> [Software Version Check] -> Plugin Scanning -> Output
```

**Phase 1: Host Discovery**

1. CIDRs are expanded into individual IP addresses. Duplicate IPs across overlapping ranges are deduplicated.
2. Each IP is pinged (500ms timeout, separate from the plugin timeout setting).
3. TCP port scanning runs against every IP, using batched asynchronous connections -- 2000 connections per batch with a 500ms connect timeout. By default, all 65535 TCP ports are scanned, with priority ordering: the Top 100 enterprise ports and any plugin-declared ScanPorts are probed first, then the remaining ports.
4. Reverse DNS resolution is attempted for every host that responds.
5. An initial OS guess is made from TTL values: TTL <= 64 is Linux/Unix, TTL <= 128 is Windows, TTL <= 255 is a Network Device.

**Phase 1b: OS Fingerprinting**

After basic discovery, a second pass enriches OS information using multiple methods:

- **CIM/WMI queries** for Windows hosts (via management ports 135, 445, 5985) to retrieve exact Windows version, build number, and domain membership.
- **SSH banner parsing** for Linux/Unix hosts to extract distribution and version information.
- **Port heuristics** as a fallback when direct interrogation is not possible.

Management ports (135, 445, 5985) are quick-probed during fingerprinting even if they were not part of the original discovery scan.

**Phase 2: Software Version Check (conditional)**

Runs only if "Software Version Check" was selected in the plugin menu. Enumerates installed software on Windows hosts via Remote Registry, PSRemoting, or WMI fallback, then applies flag rules to identify vulnerable versions. See the Software Version Check documentation for details.

**Phase 3: Vulnerability Scanning**

Each selected plugin runs against discovered hosts, but only on ports where the plugin's declared `ScanPorts` intersect with the host's discovered open ports. Plugins are never tested against ports that were not found open during discovery.

**Phase 4: Output**

All findings (software check + plugin results) are merged and exported according to the selected output formats.

### CLI Usage

```powershell
# Interactive (launches TUI menus)
.\ScottyScan.ps1 -Scan

# Fully non-interactive
.\ScottyScan.ps1 -Scan -CIDRs "192.168.100.0/24,192.168.101.0/24" -NoMenu

# With specific settings
.\ScottyScan.ps1 -Scan -CIDRs "192.168.1.0/24" -Threads 50 -TimeoutMs 3000 -NoMenu

# CIDRs from a file
.\ScottyScan.ps1 -Scan -CIDRFile .\cidrs.txt -NoMenu
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-Scan` | Activates Scan mode |
| `-CIDRs` | Comma-separated CIDR ranges (e.g., `"192.168.1.0/24,10.0.0.0/16"`) |
| `-CIDRFile` | Path to a text file with one CIDR per line |
| `-Threads` | Number of parallel threads (default: 20) |
| `-TimeoutMs` | Per-test network timeout in milliseconds (default: 5000) |
| `-Ports` | Port scanning scope: `all` (default), `top100`, `plugin`, or a comma-separated list |

### Discovery CSV Reuse

When running Scan mode interactively, ScottyScan checks the output directory for existing `Discovery_*.csv` files. If previous discovery results exist, the TUI offers a choice:

- **Reuse a previous discovery CSV** -- skips the full network sweep and loads hosts from the CSV. OS fingerprinting still runs to refresh OS data.
- **Enter new CIDRs** -- performs a fresh discovery from scratch.

This is useful when iterating on plugin testing against the same environment without repeating a lengthy 65535-port scan.

---

## List Mode (-List)

### Purpose

Scan specific hosts from a file without performing full CIDR-based network discovery. Use this when you already know which hosts to test and do not need to sweep an entire subnet.

### Execution Flow

```
Host File -> Load IPs -> Port Discovery -> OS Fingerprint -> [Software Version Check] -> Plugin Scanning -> Output
```

**Phase 1: Loading Host List + Port Discovery**

1. The host file is read. Blank lines and lines starting with `#` are ignored. Duplicate IPs are deduplicated.
2. Even though network discovery (CIDR sweep) is skipped, **port discovery still runs** against every listed host. This is necessary so that plugins know which of their ScanPorts are actually open on each target.
3. Reverse DNS and TTL-based OS guessing are performed during port discovery.

List mode also auto-detects Discovery CSV files. If the input file has the header `IP,Hostname,OS,TTL,OpenPorts`, it is treated as a Discovery CSV instead of a plain host list, and port discovery is skipped entirely (hosts and their open ports are loaded directly from the CSV).

**Phase 1b: OS Fingerprinting**

Same as Scan mode -- CIM/WMI, SSH banner, and port heuristics enrich OS data for all discovered hosts.

**Phase 2: Software Version Check (conditional)**

Same as Scan mode -- runs if selected.

**Phase 3: Vulnerability Scanning**

Same as Scan mode -- plugins run against hosts on their declared ScanPorts intersected with discovered open ports.

**Phase 4: Output**

Same as Scan mode. A Discovery CSV is also exported (unless the input was already a Discovery CSV) so results can be reused in future runs.

### CLI Usage

```powershell
# Interactive
.\ScottyScan.ps1 -List

# Non-interactive
.\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu

# With specific plugins
.\ScottyScan.ps1 -List -HostFile .\targets.txt -Plugins "DHEater-TLS,DHEater-SSH" -NoMenu

# With software version check and flag rules
.\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu \
    -Plugins "SoftwareVersionCheck,DHEater-TLS" \
    -FlagFilter "*notepad*,*7-zip*" -FlagVersion "LT8.9.1,LT24.9.0" \
    -FlagLabel "CVE-2025-15556,CVE-2024-11477"
```

### Host File Format

One IP address per line. Blank lines and `#` comment lines are ignored.

```
# Web servers
192.168.100.10
192.168.100.11
192.168.100.12

# Database servers
192.168.101.50
192.168.101.51
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-List` | Activates List mode |
| `-HostFile` | Path to a text file with one IP per line |
| `-Threads` | Number of parallel threads (default: 20) |
| `-TimeoutMs` | Per-test network timeout in milliseconds (default: 5000) |
| `-Ports` | Port scanning scope for discovery phase |

---

## Validate Mode (-Validate)

### Purpose

Import an OpenVAS findings CSV, match each finding to a ScottyScan plugin, re-test only the matched host+port+vulnerability combinations, and produce a validated before/after CSV. Use this to confirm whether OpenVAS-reported vulnerabilities have been remediated.

### Execution Flow

```
OpenVAS CSV -> Parse Findings -> Match to Plugins -> Host Discovery -> OS Fingerprint -> Re-Test Matched Combos -> Validated CSV + Output
```

**Phase 1: Loading OpenVAS CSV**

1. The CSV is parsed using a custom splitter (not `Import-Csv`) because the `nvt_name` column is the last field and can contain commas. The parser splits each row on the first 8 commas and joins the remainder as `nvt_name`.
2. IP addresses are normalized -- OpenVAS exports zero-padded IPs like `192.168.101.001`, which are converted to standard integer notation (`192.168.101.1`).
3. Unique IPs are extracted from the CSV, and host discovery runs against them to gather port and OS information.
4. OS fingerprinting enriches the discovered hosts.
5. Each finding's `nvt_name` is matched against plugin `NVTPattern` regexes. Only findings that match a loaded and selected plugin are queued for validation.
6. Matched findings are deduplicated by IP:Port:Plugin to avoid redundant tests.

**Phase 2: Validating Findings**

Each matched finding is re-tested using the corresponding plugin's `TestBlock`. The test is scoped to the exact IP and port from the OpenVAS finding -- unlike Scan/List modes which test all of a plugin's ScanPorts, Validate mode tests only the specific port the OpenVAS finding was reported on.

Test results are one of:

| Result | Meaning |
|--------|---------|
| `Vulnerable` | The vulnerability is still present |
| `Remediated` | The vulnerability has been fixed |
| `Unreachable` | The host or port did not respond |
| `Error` | The test encountered an exception |
| `Inconclusive` | The test could not determine status |

**Phase 3: Output**

A validated CSV is always produced in Validate mode, mapping each original OpenVAS finding row to its re-test result. Additional outputs (Master CSV, Summary Report, Per-Plugin CSVs) are generated based on selections.

The validated CSV preserves the original OpenVAS columns and updates the `Status` field based on re-test results.

### CLI Usage

```powershell
# Interactive
.\ScottyScan.ps1 -Validate

# Non-interactive
.\ScottyScan.ps1 -Validate -InputCSV .\openvas_findings.csv -NoMenu
```

### OpenVAS CSV Schema

The input CSV must have this column layout:

```
Status,ip,hostname,port,protocol,cvss,severity,qod,nvt_name
```

Example rows:

```
Queued,192.168.100.164,host1.example.com,3389,tcp,7.5,High,30,Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)
Pending Review,192.168.101.050,host2.example.com,22,tcp,5.3,Medium,70,Diffie-Hellman Key Exchange Insufficient DH Group Strength (SSH)
```

The `nvt_name` field is always the last column and may contain commas (e.g., the `D(HE)ater)` entries). The parser handles this correctly.

Valid `Status` values in the input: `Queued`, `Pending Review`, `Remediated`, `Confirmed Vulnerable`.

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-Validate` | Activates Validate mode |
| `-InputCSV` | Path to the OpenVAS CSV file |
| `-Threads` | Number of parallel threads (default: 20) |
| `-TimeoutMs` | Per-test network timeout in milliseconds (default: 5000) |

### IP Normalization

OpenVAS frequently exports IP addresses with zero-padded octets. ScottyScan normalizes all IPs by splitting on `.`, casting each octet to an integer, and rejoining. This ensures `192.168.101.001` matches `192.168.101.1` in all lookups.

---

## Common Elements Across All Modes

### Plugin Selection

All modes allow selecting which plugins to run. In interactive mode, this is a multi-checkbox menu. In CLI mode, use `-Plugins "Name1,Name2"`. If no `-Plugins` parameter is provided in CLI mode, all loaded plugins are selected.

The "Software Version Check" appears as a special entry in the plugin menu (internal value `__SoftwareVersionCheck__`). When selected, it enables the software inventory and flag rules engine as an additional phase between discovery and plugin scanning.

### Output Options

All modes support the same output formats, selectable via the TUI or `-Outputs` parameter:

| Output | File Pattern | Description |
|--------|-------------|-------------|
| Master CSV | `ScottyScan_Master_<timestamp>.csv` | All findings in a single CSV |
| Summary Report | `ScottyScan_Report_<timestamp>.txt` | Human-readable text summary |
| Per-Plugin CSVs | `ScottyScan_<PluginName>_<timestamp>.csv` | One CSV per plugin |
| Discovery CSV | `Discovery_<timestamp>.csv` | Host discovery results (IP, hostname, OS, TTL, open ports) |

When Software Version Check is enabled, additional outputs are produced:

| Output | File Pattern | Description |
|--------|-------------|-------------|
| Full Inventory | `SoftwareInventory_ALL_<timestamp>.csv` | All discovered software |
| Filtered Inventory | `SoftwareInventory_FILTERED_<timestamp>.csv` | Software matching filter patterns |
| Flagged Targets | `FLAGGED_<label>_TARGETS_<timestamp>.csv` | Hosts with flagged software versions |
| Flagged IPs | `FLAGGED_<label>_IPs_<timestamp>.txt` | IP-only list for deployment tools |

### Settings

All modes share these configurable settings:

| Setting | Default | Description |
|---------|---------|-------------|
| Max Threads | 20 | Number of parallel RunspacePool threads |
| Timeout (ms) | 5000 | Per-test network timeout for plugin TestBlocks |
| Discovery Ports | Plugin recommended | TCP ports to scan during host discovery |

Port scanning options:

- **All ports (1-65535)** -- Full TCP sweep with priority ordering (Top 100 + plugin ports first)
- **Top 100 enterprise ports** -- Common services only
- **Plugin recommended ports** -- Union of all selected plugins' ScanPorts
- **Custom port list** -- User-specified comma-separated ports
- **Management ports only (135, 445, 5985, 5986)** -- Automatic when only Software Version Check is selected with no vulnerability plugins

### Execution Phases Summary

The numbered phases adjust based on which features are enabled:

| Phase | Scan Mode | List Mode | Validate Mode |
|-------|-----------|-----------|---------------|
| 1 | Host Discovery (CIDR sweep) | Host List + Port Discovery | Load OpenVAS CSV + Discovery |
| 1b | OS Fingerprinting | OS Fingerprinting | OS Fingerprinting |
| 2 | Software Version Check* | Software Version Check* | Validating Findings |
| 3 | Vulnerability Scanning | Vulnerability Scanning | Output |
| 4 | Output | Output | -- |

*Software Version Check phase is conditional -- it only runs if selected. When it is not selected, Vulnerability Scanning becomes Phase 2 and Output becomes Phase 3.

### Logging

All modes write to both the console and a log file at `output_reports/logs/ScottyScan_<timestamp>.log`. The log captures plugin loading, configuration selections, every discovered host with its full port list, every plugin test result with untruncated detail, and all output file paths.
