# ScottyScan - Environment Vulnerability Scanner & Validator

## What This Project Is

ScottyScan is a PowerShell-based tool for network discovery, vulnerability scanning, and OpenVAS finding validation. It consolidates several standalone scripts we built over the past month into one menu-driven, plugin-based scanner.

The goal: run one tool that can discover your whole environment, check for known vulnerabilities, inventory installed software, and validate whether OpenVAS findings have been remediated -- all with an interactive menu so you don't need to memorize CLI parameters.

## Current State

**ScottyScan.ps1 + plugins/ are UNTESTED.** They were written in a chat-based Claude session without the ability to execute PowerShell. Expect 5-15 issues on first run. Common problems from prior scripts in this project:

- Unicode/non-ASCII characters that break PowerShell's parser (em dashes, box-drawing chars)
- `$input` is a reserved PowerShell automatic variable -- the menu system may have used it
- Byte array literals in heredocs/string injection can get mangled by the shell parser
- RunspacePool scriptblock string injection is fragile (quote escaping, variable expansion)
- `Write-Host -NoNewline` behavior varies across PS versions

**What works (has been tested in production):**
- The TLS ClientHello handshake logic (Send-TLSClientHello) -- confirmed working against Windows RDP endpoints
- The SSH KEX_INIT parser (Get-SSHKexAlgorithms) -- confirmed working against Linux SSH endpoints
- The SSH-1 banner detection -- confirmed working
- CIDR expansion logic
- RunspacePool parallelism pattern

**What has NOT been tested:**
- The interactive menu system (Show-CheckboxMenu, Show-FilePrompt, file picker)
- Config persistence (scottyscan.json load/save)
- Plugin loading from the plugins/ directory
- The scan execution engine (Invoke-PluginScan) -- the RunspacePool + string-injected helpers
- All three modes end-to-end (Scan, List, Validate)
- Output generators (CSV, summary report)

## Architecture

```
ScottyScan/
  ScottyScan.ps1              # Main script (~1550 lines)
  scottyscan.json             # Auto-created config file (persistent state)
  plugins/
    DHEater-TLS.ps1           # D(HE)ater on SSL/TLS (CVE-2002-20001)
    DHEater-SSH.ps1           # D(HE)ater on SSH
    SSH1-Deprecated.ps1       # Deprecated SSH-1 protocol
    7Zip-Version.ps1          # Outdated 7-Zip (remote registry/WMI)
    _PluginTemplate.ps1       # Template for new plugins (skipped by loader)
  legacy/
    Discover-And-Inventory.ps1  # Previous working script with features to merge
  output_reports/               # Created at runtime
    logs/
```

### Three Modes

- **-Scan**: CIDR sweep -> host discovery (ping + TCP probes) -> OS fingerprint -> run all selected plugins against discovered hosts
- **-List**: Skip discovery, read IPs from a file, run selected plugins
- **-Validate**: Read an OpenVAS CSV, match each finding to a plugin by nvt_name, test only those specific host+port+vuln combos, produce before/after validated CSV

### Plugin API

Each plugin calls `Register-Validator` with a hashtable:
- `Name` - Unique identifier
- `NVTPattern` - Regex matched against OpenVAS nvt_name column (for -Validate mode matching)
- `ScanPorts` - Which ports to test in -Scan mode
- `TestBlock` - ScriptBlock that receives `$Context` (IP, Port, Hostname, TimeoutMs, Credential) and returns `@{ Result = "Vulnerable"|"Remediated"|"Unreachable"|"Error"|"Inconclusive"; Detail = "..." }`

Helpers available inside TestBlock (injected as strings into RunspacePool):
- `Test-TCPConnect` - TCP port reachability
- `Send-TLSClientHello` - Send a TLS ClientHello with a specific cipher suite code
- `Get-SSHKexAlgorithms` - SSH banner + KEX_INIT parser

### Interactive Menu System

When run without `-NoMenu`, the script presents checkbox-style menus for:
1. Mode selection (Scan/List/Validate)
2. Plugin selection (toggle which vuln checks to run)
3. Output selection (Master CSV, summary report, per-plugin CSVs, discovery CSV)
4. Input gathering (CIDRs, host files, OpenVAS CSVs) with file picker and last-used memory

Config file (`scottyscan.json`) remembers all selections between runs.

## What Needs To Be Merged From Legacy

`legacy/Discover-And-Inventory.ps1` is a tested, working script with features that ScottyScan currently lacks. The following need to be integrated:

### 1. Detailed OS Fingerprinting (HIGH PRIORITY)

ScottyScan currently only does TTL-based guessing (<=64 = Linux, <=128 = Windows). The legacy script has:

- **WMI/CIM queries** for Windows version, build, domain membership
- **SSH banner parsing** for Linux distribution and version
- **SMB probe** for Windows version detection
- **Multiple signal fusion** -- combines TTL, open ports, WMI, SSH banner into a confidence-weighted OS determination

This should be added to the host discovery phase in `-Scan` mode. The `Invoke-HostDiscovery` function needs to be enhanced.

### 2. Software Inventory Engine (HIGH PRIORITY)

The legacy script has a complete Windows software inventory system:

- **Triple-method enumeration**: Remote Registry (fastest) -> PSRemoting fallback -> WMI fallback
- **Registry paths**: Both `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` and `HKLM:\SOFTWARE\WOW6432Node\...` for x86/x64
- **Deduplication** across methods
- **Architecture detection** (x86/x64) and install path capture
- **Wildcard filtering** via `-SoftwareFilter "*notepad*,*putty*"`

This should become an optional phase in `-Scan` mode, controlled by the output selection menu (the "Full software inventory per host" checkbox). It should produce its own `SoftwareInventory_<timestamp>.csv`.

### 3. Generic Vulnerability Flagging Engine (MEDIUM PRIORITY)

The legacy script has a rule-based flagging system for software versions:

- **Flag rules** specified as: pattern, version_rule, label
  - Example: `*notepad*,<8.9.1,CVE-2025-15556 supply chain attack`
- **Version operators**: `<`, `<=`, `>`, `>=`, `=`, `!=`, `*` (wildcard = flag any version found)
- **Input methods**: CLI parameters (`-FlagFilter`, `-FlagVersion`, `-FlagLabel`) or a CSV file (`-FlagFilterFile`)
- **Output**: Per-app remediation CSVs + IP lists for feeding into deployment scripts

This could become a software-class plugin or a built-in phase that runs after software inventory. The flag rules file is powerful -- it lets you define multiple software vulnerability checks in one file.

### Integration Approach

The cleanest way to merge these:

1. **OS fingerprinting** -- Enhance the RunspacePool discovery scriptblock in `Invoke-HostDiscovery` to add WMI/SSH probes after the basic ping+port scan
2. **Software inventory** -- Add as a new phase function `Invoke-SoftwareInventory` that runs on Windows hosts after discovery, with its own output CSV. Gate it behind the output selection menu.
3. **Flag engine** -- Add as a new menu option or a `-FlagRules` parameter that accepts a CSV file. Run it against software inventory results. Could also be implemented as a plugin that operates on inventory data rather than network probes.

## Known PowerShell Gotchas From This Project

These are real issues we hit during development. Watch for them:

1. **$input is reserved** -- PowerShell's automatic variable. Use `$userInput` or `$response` instead.
2. **Unicode breaks everything** -- Use ASCII only. No em dashes (use --), no box-drawing characters, no smart quotes.
3. **Byte arrays in heredocs** -- When injecting `[byte[]](0x00, 0x9F)` into a string for RunspacePool execution, the parser can mangle it. Test this carefully.
4. **Comparison operators in strings** -- PowerShell's parser sees `-lt`, `-gt` etc. even inside strings sometimes. The version comparison engine in the flag rules hit this.
5. **CSV with commas in fields** -- The OpenVAS CSV has commas inside the nvt_name column (e.g., `D(HE)ater)`). The parser splits on the first 8 commas and joins the remainder. Don't use Import-Csv for this file.
6. **IP normalization** -- OpenVAS exports zero-padded IPs (192.168.101.001). Always normalize to integers.
7. **Remote Registry service** -- Must be running on target Windows hosts for the fastest software enumeration method. May need to be started remotely first.
8. **WMI Win32_Product is slow** -- It can trigger MSI reconfiguration on the target. Use as last-resort fallback only.

## Testing Environment

- Windows domain environment with domain admin privileges
- Test CIDRs: 192.168.100.0/24 and 192.168.101.0/24
- Mix of Windows (Server 2012 R2 through current) and Linux (Ubuntu 22/24, FreeBSD, Fedora 33)
- ESXi hosts at .114 and .115 (SSH-1 + D(HE)ater still outstanding)
- Run from admin PowerShell on a domain-joined workstation

## Priority Order for Development

1. Get ScottyScan.ps1 running without errors (fix parser issues, test menu system)
2. Test each mode end-to-end (-Scan with a small CIDR, -List with a few hosts, -Validate with the OpenVAS CSV)
3. Merge OS fingerprinting from legacy script
4. Merge software inventory from legacy script
5. Merge flag rules engine from legacy script
6. Add any new plugins as needed

## OpenVAS CSV Format

The validation mode reads CSVs with this schema:
```
Status,ip,hostname,port,protocol,cvss,severity,qod,nvt_name
Queued,192.168.100.164,ilas1win1002.infowerks.com,3389,tcp,7.5,High,30,Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)
```

Note: nvt_name is the LAST column and can contain commas (the D(HE)ater entries do). Parse accordingly.

Status values: Queued, Pending Review, Remediated, Confirmed Vulnerable
