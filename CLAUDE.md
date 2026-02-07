# ScottyScan - Environment Vulnerability Scanner & Validator

## What This Project Is

ScottyScan is a PowerShell-based tool for network discovery, vulnerability scanning, and OpenVAS finding validation. It consolidates several standalone scripts we built over the past month into one menu-driven, plugin-based scanner.

The goal: run one tool that can discover your whole environment, check for known vulnerabilities, inventory installed software, and validate whether OpenVAS findings have been remediated -- all with an interactive menu so you don't need to memorize CLI parameters.

## Current State

**ScottyScan.ps1 has been tested in List mode against 14 hosts with all 4 plugins.** The core pipeline works end-to-end: host loading, discovery, plugin scanning, real-time output, CSV/report generation. The interactive TUI menu system has been fully rewritten and tested.

**What works (tested in production):**
- The TLS ClientHello handshake logic (Send-TLSClientHello) -- confirmed against Windows RDP endpoints
- The SSH KEX_INIT parser (Get-SSHKexAlgorithms) -- confirmed against Linux SSH endpoints
- The SSH-1 banner detection -- confirmed working
- CIDR expansion logic
- RunspacePool parallelism pattern (discovery + plugin scanning)
- Interactive TUI menu system (arrow keys, spacebar, enter, escape, back-navigation)
- Plugin loading from plugins/ directory
- Config persistence (scottyscan.json load/save with history)
- Host discovery with batched async port scanning (65535 ports)
- Scan execution engine (Invoke-PluginScan) with scoped test matrix
- Real-time console output during both discovery and plugin scanning
- Output generators (Master CSV, summary report, per-plugin CSVs, discovery CSV)
- List mode end-to-end
- Verbose log file with full discovery + test result detail

**What has NOT been tested:**
- Scan mode end-to-end (CIDR discovery -> scan)
- Validate mode end-to-end (OpenVAS CSV -> validation)
- Early exit (press E during discovery)
- The 7Zip-Version plugin (PSRemoting/WMI both fail in current test environment -- likely needs credential passthrough or domain trust)

## Architecture

```
ScottyScan/
  ScottyScan.ps1              # Main script (~2850 lines)
  scottyscan.json             # Auto-created config file (persistent state)
  dev-watch.ps1               # File watcher for live-reload during development
  plugins/
    DHEater-TLS.ps1           # D(HE)ater on SSL/TLS (CVE-2002-20001)
    DHEater-SSH.ps1           # D(HE)ater on SSH
    SSH1-Deprecated.ps1       # Deprecated SSH-1 protocol
    7Zip-Version.ps1          # Outdated 7-Zip (remote registry/WMI)
    _PluginTemplate.ps1       # Template for new plugins (skipped by loader)
  legacy/
    Discover-And-Inventory.ps1  # Previous working script with features to merge
  input_files/                  # Host lists, OpenVAS CSVs (gitignored)
  output_reports/               # Created at runtime (gitignored)
    logs/                       # Verbose per-run log files
```

### Three Modes

- **-Scan**: CIDR sweep -> host discovery (ping + TCP probes) -> OS fingerprint -> run all selected plugins against discovered hosts
- **-List**: Skip discovery, read IPs from a file, run selected plugins. Still performs port discovery on listed hosts.
- **-Validate**: Read an OpenVAS CSV, match each finding to a plugin by nvt_name, test only those specific host+port+vuln combos, produce before/after validated CSV

### Plugin API

Each plugin calls `Register-Validator` with a hashtable:
- `Name` - Unique identifier
- `NVTPattern` - Regex matched against OpenVAS nvt_name column (for -Validate mode matching)
- `ScanPorts` - Which ports to test in -Scan/-List mode. Empty array = software-class plugin (runs once per host, no port).
- `TestBlock` - ScriptBlock that receives `$Context` (IP, Port, Hostname, TimeoutMs, Credential) and returns `@{ Result = "Vulnerable"|"Remediated"|"Unreachable"|"Error"|"Inconclusive"; Detail = "..." }`

Test matrix scoping: plugins are ONLY tested against their declared `ScanPorts`, NOT every discovered port. Software-class plugins (ScanPorts = @()) run once per host with port 0 as a sentinel.

Helpers available inside TestBlock (injected as strings into RunspacePool):
- `Test-TCPConnect` - TCP port reachability
- `Send-TLSClientHello` - Send a TLS ClientHello with a specific cipher suite code
- `Get-SSHKexAlgorithms` - SSH banner + KEX_INIT parser

### Interactive TUI Menu System

Full keyboard-navigable TUI using `[Console]::SetCursorPosition` + `[Console]::Write` for scroll-free rendering:
- Arrow Up/Down: Move highlight cursor (wraps around)
- Space: Toggle checkbox (multi) or select radio (single)
- Enter: Confirm and proceed
- Escape: Go back to previous step (or exit at first menu)
- A/N: Select All / None (multi-select only)

State machine flow with back-navigation:
1. Mode select (Scan/List/Validate) -> Esc = exit
2. Plugin select (multi-checkbox) -> Esc = back to 1
3. Output select (multi-checkbox) -> Esc = back to 2
4. Settings (threads/timeout/ports) -> Esc = back to 3
5. Mode-specific input (CIDRs/file/CSV) -> Esc = back to 4
6. Confirmation screen -> Esc = back to 5, Enter = execute

File input prompts use a two-panel TUI: left panel shows last 5 history entries, right panel (Left arrow) has Browse/Type manually actions.

Config file (`scottyscan.json`) remembers all selections between runs including input history.

### Port Scanning

Default: all 65535 ports. Configurable via Settings menu:
- **All ports (1-65535)**: Full TCP sweep with priority ordering (Top 100 + plugin ports first, then remainder)
- **Top 100 enterprise ports**: Common services only
- **Custom port list**: User-specified CSV

Port scanning uses batched async TCP connections (2000 per batch, 500ms connect timeout) with progress reported via `[hashtable]::Synchronized()` back to the main thread.

### Real-Time Console Output

**Discovery phase**: Fixed-position 15-row display block (redrawn in place via Write-LineAt):
- Host results window (last 6 entries)
- Open port discoveries window (last 6 entries + total counter)
- Spinner with host count, port count, current port range %, elapsed time
- Press [E] to end scan early (with Y/N confirmation, harvests partial results)

**Plugin scan phase**: Scrolling output with each test result as it completes, plus spinner with elapsed time.

### Logging

`Write-Log` writes to both console and `output_reports/logs/ScottyScan_<timestamp>.log`. Supports `-Silent` switch for log-only writes during TUI rendering.

Log captures:
- Plugin loading
- Mode, plugin, and config selections
- Every discovered host with full port list
- Every plugin test result with full (untruncated) detail
- Output file paths
- Early exit events

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
9. **Write-Host during TUI rendering** -- Never call Write-Host (or Write-Log without -Silent) inside a Write-LineAt rendering loop. It corrupts the fixed-position display. Use Write-Log -Silent for file-only logging during TUI sections.
10. **ASCII art in heredocs** -- Backslashes and special characters in banner heredocs are fragile during editing. The banner has been manually corrected multiple times. Don't edit it unless necessary.
11. **[Console]::KeyAvailable** -- Use `[System.ConsoleKey]::E` not `[ConsoleKeyCode]::E` for key comparisons.

## Testing Environment

- Windows domain environment with domain admin privileges
- Test CIDRs: 192.168.100.0/24 and 192.168.101.0/24
- Mix of Windows (Server 2012 R2 through current) and Linux (Ubuntu 22/24, FreeBSD, Fedora 33)
- ESXi hosts at .17 and .26 (D(HE)ater on SSH confirmed vulnerable, 5 DHE kex algorithms)
- Run from admin PowerShell on a domain-joined workstation
- Parser check: `powershell -NoProfile -Command '[System.Management.Automation.Language.Parser]::ParseFile("ScottyScan.ps1", [ref]$null, [ref]$errors); $errors.Count'`

## Priority Order for Development

1. ~~Get ScottyScan.ps1 running without errors~~ DONE
2. ~~Test List mode end-to-end~~ DONE
3. Test Scan mode end-to-end (-Scan with a small CIDR)
4. Test Validate mode end-to-end (-Validate with the OpenVAS CSV)
5. Fix 7Zip-Version plugin (credential passthrough for PSRemoting/WMI)
6. Merge OS fingerprinting from legacy script
7. Merge software inventory from legacy script
8. Merge flag rules engine from legacy script
9. Add any new plugins as needed

## OpenVAS CSV Format

The validation mode reads CSVs with this schema:
```
Status,ip,hostname,port,protocol,cvss,severity,qod,nvt_name
Queued,192.168.100.164,ilas1win1002.infowerks.com,3389,tcp,7.5,High,30,Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)
```

Note: nvt_name is the LAST column and can contain commas (the D(HE)ater entries do). Parse accordingly.

Status values: Queued, Pending Review, Remediated, Confirmed Vulnerable

## Key Functions Reference

| Function | Lines | Purpose |
|---|---|---|
| `Build-PortList` | ~134 | Resolves port config to int[] with priority ordering |
| `Write-Log` | ~221 | Console + file logging with -Silent switch |
| `Write-LineAt` | ~278 | TUI primitive: write at absolute row, no scroll |
| `Show-InteractiveMenu` | ~330 | Arrow-key navigable single/multi-select menu |
| `Show-FilePrompt` | ~680 | Two-panel file history + action TUI |
| `Show-SettingsMenu` | ~870 | Thread/timeout/port configuration |
| `Show-ConfirmationScreen` | ~1050 | Pre-execution summary with Enter/Esc |
| `Invoke-HostDiscovery` | ~1600 | Batched async port scan with TUI progress |
| `Invoke-PluginScan` | ~1960 | Scoped test matrix with real-time results |
| `Export-MasterCSV` | ~2050 | CSV output generator |
| `Export-SummaryReport` | ~2070 | Human-readable text report |
