# Chapter 12: Function Reference

Complete function reference for `ScottyScan.ps1`. Functions are listed by category with approximate line numbers, parameters, return values, and purpose. Line numbers are approximate and may shift as the codebase evolves.

ScottyScan.ps1 is approximately 4800 lines. All functions are defined at the top of the file, with the main entry point starting around line 4096.

---

## Core Infrastructure

### Build-PortList

| | |
|---|---|
| **Line** | ~170 |
| **Purpose** | Resolves a port configuration string into an `int[]` port list, merged with plugin-declared ScanPorts. When scanning all ports, puts well-known ports first for faster initial results. |
| **Parameters** | `[string]$PortString` -- port config: `""` or `"all"` = 1-65535, `"top100"` = Top 100 enterprise ports, `"plugin"` = only ports declared by selected plugins, or a CSV of port numbers. `[array]$SelectedPlugins` -- array of plugin hashtables (ScanPorts are merged in). `[switch]$SoftwareCheckOnly` -- when set and no explicit port config, restricts to management ports (135, 445, 5985, 5986). |
| **Returns** | `int[]` -- sorted port list with priority ordering (Top 100 + plugin ports first, then remainder when doing full scan). |

### Get-PortDisplayString

| | |
|---|---|
| **Line** | ~230 |
| **Purpose** | Returns a human-readable description of the port configuration for display in menus and confirmation screens. |
| **Parameters** | `[string]$PortString`, `[switch]$SoftwareCheckOnly`, `[array]$SelectedPlugins` |
| **Returns** | `string` -- e.g., `"All ports (1-65535)"`, `"Top 100 enterprise ports"`, `"Plugin recommended (4 ports)"`, `"Management ports only (135, 445, 5985, 5986)"`, or the port list itself if 10 or fewer. |

### Write-Banner

| | |
|---|---|
| **Line** | ~266 |
| **Purpose** | Displays the ScottyScan ASCII art banner to the console using `Write-Host`. Used at script startup (non-TUI context). |
| **Parameters** | None |
| **Returns** | Nothing |

### Write-Section

| | |
|---|---|
| **Line** | ~282 |
| **Purpose** | Writes a section header to the console and log. Used to mark phase transitions (e.g., "PHASE 1: Host Discovery"). |
| **Parameters** | `[string]$Title` |
| **Returns** | Nothing |

### Write-Log

| | |
|---|---|
| **Line** | ~289 |
| **Purpose** | Dual console + file logger. Writes a timestamped, level-tagged message to both the console (with color coding) and the log file. |
| **Parameters** | `[string]$Message` -- log message text. `[string]$Level` -- one of `"INFO"`, `"ERROR"`, `"WARN"`, `"OK"`, `"DEBUG"`. Default: `"INFO"`. `[switch]$Silent` -- when set, writes to log file only (no console output). Critical for use during TUI rendering. |
| **Returns** | Nothing |
| **Notes** | Color mapping: ERROR=Red, WARN=Yellow, OK=Green, DEBUG=DarkGray, INFO=Gray. Log file path is set in `$script:LogFile` during initialization. |

### Write-Status

| | |
|---|---|
| **Line** | ~308 |
| **Purpose** | Writes a label-value pair to the console with aligned formatting. Used for status display in confirmation screens. |
| **Parameters** | `[string]$Label`, `[string]$Value`, `[string]$Color` (default: `"White"`) |
| **Returns** | Nothing |

### Test-IsConsoleHost

| | |
|---|---|
| **Line** | ~318 |
| **Purpose** | Returns `$true` if running in a real console host (supports `ReadKey` for TUI), `$false` for ISE or other non-console hosts. |
| **Parameters** | None |
| **Returns** | `bool` |

---

## TUI Drawing Primitives

These functions write directly to the console buffer at absolute row positions using `[Console]::SetCursorPosition` and `[Console]::Write` to avoid terminal scrolling.

### script:Get-ConsoleWidth

| | |
|---|---|
| **Line** | ~331 |
| **Purpose** | Returns the current console buffer width in characters. Falls back to 80 if width cannot be determined. |
| **Parameters** | None |
| **Returns** | `int` |

### script:Get-ConsoleHeight

| | |
|---|---|
| **Line** | ~345 |
| **Purpose** | Returns the current console window height in rows. Falls back to 25 if height cannot be determined. |
| **Parameters** | None |
| **Returns** | `int` |

### script:Write-LineAt

| | |
|---|---|
| **Line** | ~359 |
| **Purpose** | TUI primitive: writes a string at an absolute console row, padded to full width, with foreground and background color. Does NOT advance the cursor to a new line -- no scrolling occurs. Leaves the last column empty to prevent console wrapping. |
| **Parameters** | `[int]$Row` -- zero-based row number. `[string]$Text` -- text to write. `[ConsoleColor]$Fg` -- foreground color (default: Gray). `[ConsoleColor]$Bg` -- background color (default: Black). |
| **Returns** | Nothing |

### script:Clear-Screen

| | |
|---|---|
| **Line** | ~388 |
| **Purpose** | Clears the entire visible console window by writing spaces to every row. Resets cursor to (0,0). |
| **Parameters** | None |
| **Returns** | Nothing |

### script:Draw-Banner

| | |
|---|---|
| **Line** | ~409 |
| **Purpose** | Draws the ScottyScan ASCII art banner at the top of the screen (rows 0 through ~10) using `Write-LineAt`. Includes version and build timestamp. |
| **Parameters** | None |
| **Returns** | `int` -- the next available row after the banner (for subsequent TUI content). |

---

## Interactive TUI Menus

### Show-InteractiveMenu

| | |
|---|---|
| **Line** | ~436 |
| **Purpose** | Full-screen keyboard-navigable TUI menu. Supports both single-select (radio) and multi-select (checkbox) modes. Handles arrow keys, spacebar (toggle), Enter (confirm), Escape (cancel/back), and optional Select All/None action buttons. Falls back to `Show-FallbackMenu` in non-console hosts. |
| **Parameters** | `[string]$Title` -- menu title displayed above items. `[array]$Items` -- array of hashtables, each with `Name`, `Value`, `Selected`, and optional `Description`. `[switch]$SingleSelect` -- radio mode (only one selection allowed). `[switch]$AllowSelectAll` -- prepends ALL/NONE action buttons. `[switch]$IsRootMenu` -- marks this as the root menu (Escape exits rather than going back). |
| **Returns** | `array` of selected `Value` entries, or `$null` if user pressed Escape. |

### Show-FallbackMenu

| | |
|---|---|
| **Line** | ~716 |
| **Purpose** | Read-Host based fallback menu for non-console hosts (ISE, VS Code integrated terminal, etc.). Provides the same selection functionality as `Show-InteractiveMenu` without requiring `[Console]::ReadKey`. |
| **Parameters** | `[string]$Title`, `[System.Collections.ArrayList]$Selections`, `[switch]$SingleSelect`, `[switch]$AllowSelectAll` |
| **Returns** | `array` of selected `Value` entries. |

### Show-FilePrompt

| | |
|---|---|
| **Line** | ~789 |
| **Purpose** | Two-panel TUI input selector for file paths. Right panel shows recent history entries (up to 5, navigable with arrow keys). Left arrow switches to action panel with Browse (GUI file picker) and Type manually options. Supports non-console fallback. |
| **Parameters** | `[string]$Title` -- prompt title. `[string[]]$History` -- previously used paths. `[string]$Filter` -- file dialog filter string. `[string]$TypePrompt` -- prompt text for manual path entry. `[switch]$MustExist` -- validates that the selected file exists. |
| **Returns** | `string` -- selected file path, or `$null` on Escape. |

### Show-FilePicker

| | |
|---|---|
| **Line** | ~1071 |
| **Purpose** | Opens a Windows Forms `OpenFileDialog` for GUI file selection. Used by `Show-FilePrompt` when the user selects "Browse for file...". |
| **Parameters** | `[string]$Filter` -- file type filter. `[string]$LastFolder` -- initial directory. |
| **Returns** | `string` -- selected file path, or `$null` if cancelled or unavailable. |

### Show-TextPrompt

| | |
|---|---|
| **Line** | ~1095 |
| **Purpose** | Full-screen text prompt for single-value input (thread count, timeout, custom ports, etc.). Draws on the TUI layout with banner. |
| **Parameters** | `[string]$Prompt` -- prompt text. `[string]$Default` -- default value if user presses Enter with no input. `[string]$LastValue` -- previously used value (takes precedence over Default). |
| **Returns** | `string` -- user input, or default/last value if empty input. |

### Show-SettingsMenu

| | |
|---|---|
| **Line** | ~1135 |
| **Purpose** | Interactive settings menu for thread count, timeout, and port configuration. Each setting is a selectable row that opens a sub-prompt. Port selection offers All ports, Top 100, Plugin recommended, and Custom options. |
| **Parameters** | `[int]$CurrentThreads`, `[int]$CurrentTimeout`, `[string]$CurrentPorts`, `[switch]$SoftwareCheckOnly`, `[array]$SelectedPlugins` |
| **Returns** | `hashtable` -- `@{ Threads = int; Timeout = int; Ports = string }`, or `$null` on Escape. |

### Show-ConfirmationScreen

| | |
|---|---|
| **Line** | ~1239 |
| **Purpose** | Full-screen pre-execution summary showing all selected options (mode, plugins, outputs, threads, timeout, ports, input source). User presses Enter to execute or Escape to go back. |
| **Parameters** | `[string]$Mode`, `[string[]]$PluginNames`, `[string[]]$OutputNames`, `[int]$Threads`, `[int]$Timeout`, `[string]$Ports`, `[string]$InputDetail`, `[string]$SoftwareCheckDetail`, `[switch]$SoftwareCheckOnly`, `[string]$CredentialDisplay`, `[array]$SelectedPlugins` |
| **Returns** | `bool` -- `$true` on Enter (execute), `$false` on Escape (go back). |

### Get-ModeInput

| | |
|---|---|
| **Line** | ~1326 |
| **Purpose** | Gathers mode-specific input: CIDRs for Scan mode, host file path for List mode, or OpenVAS CSV path for Validate mode. Uses two-panel TUI with history. Supports Discovery CSV reuse in both Scan and List modes. |
| **Parameters** | `[string]$Mode` -- `"Scan"`, `"List"`, or `"Validate"`. `[PSCustomObject]$Config` -- current config object for history lookup. |
| **Returns** | `hashtable` -- mode-specific keys (e.g., `@{ CIDRList; CIDRFile; RawInput }` for Scan, `@{ HostFile }` for List, `@{ CSVPath }` for Validate), or `$null` on Escape. May also return `@{ DiscoveryCSV }` if user chose to reuse previous discovery results. |

---

## Configuration and State

### Load-Config

| | |
|---|---|
| **Line** | ~1458 |
| **Purpose** | Loads `scottyscan.json` from the script directory into `$script:Config`. If the file does not exist or fails to parse, initializes a default config object with sensible defaults. |
| **Parameters** | None |
| **Returns** | Nothing (sets `$script:Config`) |

### Save-Config

| | |
|---|---|
| **Line** | ~1490 |
| **Purpose** | Serializes `$script:Config` to `scottyscan.json` with JSON depth 5. |
| **Parameters** | None |
| **Returns** | Nothing |

### Update-ConfigValue

| | |
|---|---|
| **Line** | ~1498 |
| **Purpose** | Sets a single key-value pair on `$script:Config`. Creates the property if it does not exist (via `Add-Member -Force`). |
| **Parameters** | `[string]$Key`, `$Value` |
| **Returns** | Nothing |

### Push-InputHistory

| | |
|---|---|
| **Line** | ~1507 |
| **Purpose** | Pushes a value to the front of a config history array, deduplicating and capping at 5 entries. Used to track recently used file paths and CIDRs. |
| **Parameters** | `[string]$ConfigKey` -- the config property name (e.g., `"HostFileHistory"`). `[string]$Value` -- the path/value to push. |
| **Returns** | Nothing |

### Get-InputHistory

| | |
|---|---|
| **Line** | ~1523 |
| **Purpose** | Returns the history array for a given config key. Migrates from legacy `Last*` fields (e.g., `LastHostFile`) if the history array is empty. |
| **Parameters** | `[string]$HistoryKey` -- config property for the history array. `[string]$LegacyKey` -- config property for the old single-value field. |
| **Returns** | `string[]` -- history entries, most recent first. |

---

## Plugin System

### Register-Validator

| | |
|---|---|
| **Line** | ~1547 |
| **Purpose** | Called by each plugin file to register a validator (test definition) with the scanner. Validates that required keys are present and sets defaults for optional keys. |
| **Parameters** | `[hashtable]$Validator` -- must contain `Name`, `NVTPattern`, `TestBlock`. Optional: `Priority` (default 100), `PortFilter`, `ProtoFilter`, `Description`, `ScanPorts` (default `@()`), `Category` (default `"General"`). |
| **Returns** | Nothing (adds to `$script:Validators` list) |

### Load-Plugins

| | |
|---|---|
| **Line** | ~1564 |
| **Purpose** | Dot-sources all `.ps1` files from the plugins directory, skipping files starting with underscore. Each plugin file calls `Register-Validator` during dot-sourcing. |
| **Parameters** | `[string]$Dir` -- plugin directory path. Default: `$PSScriptRoot\plugins`. |
| **Returns** | Nothing (populates `$script:Validators`) |

### Find-Validator

| | |
|---|---|
| **Line** | ~1586 |
| **Purpose** | Finds the best matching validator for a given NVT name (from OpenVAS CSV), optionally filtered by port and protocol. Returns the first match by priority order. Used in Validate mode. |
| **Parameters** | `[string]$NVTName` -- the OpenVAS nvt_name field. `[string]$Port` -- port number. `[string]$Protocol` -- `"tcp"` or `"udp"`. |
| **Returns** | `hashtable` -- the matching validator, or `$null` if no match. |

---

## Network Helpers (Main Thread Versions)

These are the "real" function definitions used in the main thread. Stringified copies exist in `$script:HelperFunctionsString` for injection into RunspacePool threads.

### Test-TCPConnect

| | |
|---|---|
| **Line** | ~1602 |
| **Purpose** | Tests TCP port reachability using async connection with timeout. |
| **Parameters** | `[string]$IP`, `[int]$Port`, `[int]$TimeoutMs` |
| **Returns** | `$true` (port open), `$false` (connection refused), or `$null` (timeout/unreachable). |

### Send-TLSClientHello

| | |
|---|---|
| **Line** | ~1615 |
| **Purpose** | Sends a raw TLS ClientHello message with a specific cipher suite code to test whether the server accepts it. Constructs a minimal TLS 1.2 ClientHello with TLS 1.3 supported_versions extension. |
| **Parameters** | `[string]$IP`, `[int]$Port`, `[byte[]]$CipherCode` -- 2-byte cipher suite identifier (e.g., `0x00, 0x9F` for DHE_RSA_WITH_AES_256_GCM_SHA384). `[int]$TimeoutMs` |
| **Returns** | `$true` (cipher accepted -- ServerHello received), `$false` (cipher rejected), or `$null` (connection error). |

### Get-SSHKexAlgorithms

| | |
|---|---|
| **Line** | ~1657 |
| **Purpose** | Connects to an SSH server, reads its banner, sends an SSH-2.0 identification string, reads the KEX_INIT packet, and parses out the list of key exchange algorithms. |
| **Parameters** | `[string]$IP`, `[int]$Port`, `[int]$TimeoutMs` |
| **Returns** | `hashtable` -- `@{ Banner = "SSH-2.0-..."; KexAlgorithms = @("curve25519-sha256", "diffie-hellman-group14-sha256", ...) }`, or `$null` on connection failure. |

### Get-OSFromBanner

| | |
|---|---|
| **Line** | ~1784 |
| **Purpose** | Extracts an OS distribution name from an SSH banner string using pattern matching. Recognizes Ubuntu, Debian, Raspbian, FreeBSD, OpenBSD, NetBSD, Fedora, CentOS, AlmaLinux, Rocky Linux, RHEL, SUSE, Arch Linux, ESXi, and Cisco IOS. |
| **Parameters** | `[string]$Banner` |
| **Returns** | `string` -- OS name, or empty string if no match. |
| **Notes** | This function is defined inside the `$script:HelperFunctionsString` here-string block for RunspacePool injection, not as a standalone function. |

---

## Version Comparison Engine

### Compare-VersionStrings

| | |
|---|---|
| **Line** | ~1810 |
| **Purpose** | Compares two dotted version strings (e.g., `"24.9.0"` vs `"23.01"`). Handles version strings with different numbers of segments by padding with zeros. |
| **Parameters** | `[string]$Current` -- the version being evaluated. `[string]$Target` -- the version to compare against. |
| **Returns** | `int` -- `-1` (Current < Target), `0` (equal), `1` (Current > Target). Returns `-1` if either input is null/empty. |

### Test-VersionAgainstRule

| | |
|---|---|
| **Line** | ~1838 |
| **Purpose** | Tests whether a software version matches a flag rule expression. A match means the version IS flagged (vulnerable/outdated). Supports both text operators (LT, LE, GT, GE, EQ, NE) and symbol operators (<, <=, >, >=, =, !=). Wildcard `*` flags all versions. |
| **Parameters** | `[string]$Version` -- the installed version. `[string]$Rule` -- the rule expression (e.g., `"LT8.9.1"`, `"<24.9.0"`, `"*"`). |
| **Returns** | `bool` -- `$true` if the version is flagged, `$false` if it passes. Missing versions are always flagged (assume vulnerable). |

### Get-VersionStatus

| | |
|---|---|
| **Line** | ~1896 |
| **Purpose** | Returns a human-readable status string for a version evaluated against a rule. Used for display in reports and logs. |
| **Parameters** | `[string]$Version`, `[string]$Rule` |
| **Returns** | `string` -- e.g., `"*** FLAGGED *** (v23.01 matches rule: LT24.9.0)"` or `"OK (v24.9.0 passes rule: LT24.9.0)"`. |

### Import-FlagRules

| | |
|---|---|
| **Line** | ~1917 |
| **Purpose** | Parses flag rules from CLI parameters or a CSV rule file. CLI parameters use positional correspondence across comma-separated lists. File format: `pattern,versionrule,label` per line (lines starting with `#` are comments). |
| **Parameters** | `[string]$FlagFilter` -- comma-separated wildcard patterns. `[string]$FlagVersion` -- comma-separated version rules. `[string]$FlagLabel` -- comma-separated labels. `[string]$FlagFilterFile` -- path to CSV rule file. |
| **Returns** | `List[PSObject]` -- array of rule objects, each with `Pattern`, `VersionRule`, and `Label` properties. |

---

## Software Enumeration

### Get-SoftwareFromRegistry

| | |
|---|---|
| **Line** | ~2046 |
| **Purpose** | Enumerates installed software on a remote Windows host via Remote Registry. Reads both 64-bit (`Uninstall`) and 32-bit (`WOW6432Node\Uninstall`) registry hives using `[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey`. |
| **Parameters** | `[string]$ComputerName` |
| **Returns** | `List[PSObject]` -- array of software entries, each with `ComputerName`, `Name`, `Version`, `Publisher`, `InstallDate`, `InstallPath`, `Architecture` (x86/x64), `Source` ("Registry"). |
| **Notes** | Requires the Remote Registry service to be running on the target. Fastest enumeration method. |

### Get-SoftwareFromPSRemoting

| | |
|---|---|
| **Line** | ~2089 |
| **Purpose** | Fallback software enumeration via PSRemoting (`Invoke-Command`). Runs a scriptblock on the remote host that reads the same Uninstall registry keys locally. |
| **Parameters** | `[string]$ComputerName`, `[PSCredential]$Credential` (optional) |
| **Returns** | `List[PSObject]` -- same format as `Get-SoftwareFromRegistry`, with `Source` = `"PSRemoting"`. |
| **Notes** | Requires WinRM to be enabled on the target (ports 5985/5986). |

### Get-SoftwareFromWMI

| | |
|---|---|
| **Line** | ~2145 |
| **Purpose** | Last-resort software enumeration via WMI `Win32_Product` class. Slow and can trigger MSI reconfiguration on the target. |
| **Parameters** | `[string]$ComputerName`, `[PSCredential]$Credential` (optional) |
| **Returns** | `List[PSObject]` -- same format, with `Source` = `"WMI"`. Architecture is always empty. |
| **Notes** | Can take several minutes per host. Use only after Registry and PSRemoting fail. |

### Invoke-SoftwareCheck

| | |
|---|---|
| **Line** | ~3171 |
| **Purpose** | Main software check orchestrator. Filters to Windows hosts only (by OS guess or port 445 open). Dispatches one RunspacePool job per host. Each job tries Registry -> PSRemoting -> WMI fallback chain, deduplicates results, and applies flag rules. |
| **Parameters** | `[array]$Targets` -- array of `@{ IP; Hostname; OS; OpenPorts }`. `[array]$FlagRules` -- array of `@{ Pattern; VersionRule; Label }`. `[string[]]$SoftwareFilters` -- wildcard patterns for inventory filtering. `[int]$MaxThreads`, `[PSCredential]$Credential`, `[string]$OutDir`. |
| **Returns** | `array` -- findings in the same format as `Invoke-PluginScan`: `@{ IP; Port; Hostname; PluginName; Result; Detail }`. Port is always 0 (sentinel for software-class checks). |

### Export-SoftwareOutputs

| | |
|---|---|
| **Line** | ~3392 |
| **Purpose** | Generates all software-related output files from the software check results. |
| **Parameters** | `[List[PSObject]]$AllInventory` -- per-host inventory data. `[List[PSObject]]$AllFlagged` -- flagged software entries. `[List[PSObject]]$AllFlagResults` -- all flag evaluation results. `[array]$FlagRules`, `[string[]]$SoftwareFilters`, `[string]$OutDir`. |
| **Returns** | Nothing (writes files) |
| **Output files** | `SoftwareInventory_ALL_*.csv` -- full inventory (filtered by patterns if provided). `FLAGGED_ALL_TARGETS_*.csv` -- master flagged CSV. `FLAGGED_ALL_IPs_*.txt` -- unique IPs with flagged software. `FLAGGED_<pattern>_TARGETS_*.csv` and `FLAGGED_<pattern>_IPs_*.txt` -- per-rule breakdowns. |

---

## CIDR and Discovery

### Expand-CIDR

| | |
|---|---|
| **Line** | ~2303 |
| **Purpose** | Expands a CIDR notation string into an array of individual IP addresses. Excludes network and broadcast addresses. |
| **Parameters** | `[string]$CIDR` -- e.g., `"192.168.100.0/24"` |
| **Returns** | `ArrayList` of IP strings -- e.g., `"192.168.100.1"` through `"192.168.100.254"` for a /24. Returns empty array if input is malformed. |

### Invoke-HostDiscovery

| | |
|---|---|
| **Line** | ~2326 |
| **Purpose** | Batched async port scan with real-time TUI progress display. For each IP: tests all ports in the port list using batched async TCP connections (2000 per batch, 500ms connect timeout), resolves hostname via DNS, guesses OS from TTL and open port patterns. Reports progress via synchronized hashtable back to main thread. Supports early exit via [E] key. |
| **Parameters** | `[string[]]$IPList` -- IPs to scan. `[int]$MaxThreads` -- RunspacePool size. `[int]$TimeoutMs` -- per-port timeout. `[int[]]$PortList` -- ports to scan per host. |
| **Returns** | `ArrayList` of host hashtables: `@{ IP; Alive; OpenPorts; Hostname; OS; TTL }`. Only alive hosts (at least one open port) are included. |
| **Notes** | Displays a 15-row fixed-position TUI block with host results, port discoveries, and spinner. Uses `Write-LineAt` for scroll-free rendering. |

### Invoke-OSFingerprint

| | |
|---|---|
| **Line** | ~2683 |
| **Purpose** | Enriches discovered hosts with detailed OS information. Uses multiple detection methods: CIM/WMI queries for Windows (version, build, edition, domain), SSH banner parsing for Linux distributions, and port-based heuristics. Modifies hosts in-place (updates `.OS`, adds `.DetectMethod`). Quick-probes management ports (135, 445, 5985) that may not have been in the discovery scan. |
| **Parameters** | `[System.Collections.ArrayList]$LiveHosts` -- hosts from `Invoke-HostDiscovery` or `Import-DiscoveryCSV`. `[int]$MaxThreads` (capped at 20). `[int]$TimeoutMs`. `[PSCredential]$Credential` (optional). |
| **Returns** | Nothing (modifies `$LiveHosts` in-place). |
| **Notes** | Runs as Phase 1b between host discovery and plugin scanning. Each host is processed in its own RunspacePool thread. |

---

## Scanning Engine

### Invoke-PluginScan

| | |
|---|---|
| **Line** | ~2981 |
| **Purpose** | Runs selected plugins against a set of targets with scoped test matrix. Each plugin is only tested against its declared `ScanPorts` intersected with the host's discovered open ports. Software-class plugins (empty ScanPorts) run once per host with port 0 as sentinel. Results are output in real-time to the console. |
| **Parameters** | `[array]$Targets` -- array of `@{ IP; Port; Hostname; OS; OpenPorts }`. Port is set for Validate mode (exact combo), null for Scan/List mode. `[array]$SelectedPlugins` -- validator hashtables from `$script:Validators`. `[int]$MaxThreads`. `[int]$TimeoutMs`. |
| **Returns** | `array` of finding hashtables: `@{ IP; Port; Hostname; OS; PluginName; Result; Detail }`. |
| **Notes** | Uses RunspacePool with helper functions injected via `$script:HelperFunctionsString`. Each test is a separate RunspacePool job. |

---

## Output Generation

### Export-MasterCSV

| | |
|---|---|
| **Line** | ~3512 |
| **Purpose** | Generates the unified CSV file containing all findings from all plugins and Software Version Check. |
| **Parameters** | `[array]$Findings` -- finding hashtables. `[string]$Path` -- output file path. |
| **Returns** | Nothing (writes file) |
| **CSV columns** | `IP, Hostname, OS, Port, Plugin, Result, Detail, Timestamp` |

### Export-SummaryReport

| | |
|---|---|
| **Line** | ~3529 |
| **Purpose** | Generates a human-readable text report with scan parameters, totals, per-plugin result breakdowns, and detailed sections for Vulnerable, Unreachable, and Remediated findings. |
| **Parameters** | `[array]$Findings`, `[string]$Path`, `[string]$Mode` |
| **Returns** | Nothing (writes file) |
| **Sections** | Summary (total/vulnerable/remediated/unreachable/error/inconclusive counts), By Plugin (per-plugin result breakdown), Vulnerable detail (IP, hostname, port, plugin, detail), Unreachable list, Remediated list. |

### Import-DiscoveryCSV

| | |
|---|---|
| **Line** | ~3621 |
| **Purpose** | Reads a Discovery CSV (previously exported by `Export-DiscoveryCSV`) and returns host hashtables in the same format as `Invoke-HostDiscovery` output. Enables Discovery CSV reuse to skip host discovery. |
| **Parameters** | `[string]$Path` |
| **Returns** | `ArrayList` of `@{ IP; Alive; Hostname; OS; TTL; OpenPorts }`. |
| **CSV format** | `IP,Hostname,OS,TTL,OpenPorts` (ports semicolon-delimited). |

### Export-DiscoveryCSV

| | |
|---|---|
| **Line** | ~3664 |
| **Purpose** | Exports discovered hosts to a CSV for later reuse. Ports are semicolon-delimited within the OpenPorts column. |
| **Parameters** | `[array]$Hosts`, `[string]$Path` |
| **Returns** | Nothing (writes file) |

### Export-ValidateCSV

| | |
|---|---|
| **Line** | ~3677 |
| **Purpose** | For Validate mode: writes back the original OpenVAS CSV with validation columns appended. Optionally updates the Status column based on validation results (Remediated/Confirmed Vulnerable). |
| **Parameters** | `[array]$OriginalRows` -- parsed OpenVAS rows. `[hashtable]$ResultLookup` -- keyed by `"IP:Port"`, values are finding hashtables. `[string]$Path`. `[switch]$UpdateStatus` -- update the Status column. |
| **Returns** | Nothing (writes file) |
| **Appended columns** | `Validation_Result, Validation_Detail, Validation_Plugin, Validation_Timestamp` |

### Import-OpenVASCSV

| | |
|---|---|
| **Line** | ~3736 |
| **Purpose** | Parses an OpenVAS CSV file, handling commas embedded in the `nvt_name` column (which is the last column). Splits each line on commas, takes the first 8 fields positionally, and joins the remainder as `nvt_name`. |
| **Parameters** | `[string]$Path` |
| **Returns** | `ArrayList` of ordered hashtables: `@{ Status; ip; hostname; port; protocol; cvss; severity; qod; nvt_name }`. |

### Export-Results

| | |
|---|---|
| **Line** | ~4074 |
| **Purpose** | Output dispatcher. Calls `Export-MasterCSV`, `Export-SummaryReport`, and per-plugin CSVs based on the user's output selections. |
| **Parameters** | `[array]$Findings`, `[array]$SelectedOutputs` -- array of output type strings (`"MasterCSV"`, `"SummaryReport"`, `"PerPluginCSV"`). `[string]$OutDir`, `[string]$Mode`. |
| **Returns** | Nothing |

---

## Mode Orchestrators

### Invoke-ScanMode

| | |
|---|---|
| **Line** | ~3766 |
| **Purpose** | Network scan mode orchestrator. Expands CIDRs, runs host discovery (or loads from Discovery CSV), runs OS fingerprinting, optionally runs Software Version Check, runs plugin scanning, and exports all results. |
| **Parameters** | `[string[]]$CIDRList`, `[array]$SelectedPlugins`, `[array]$SelectedOutputs`, `[int]$Threads`, `[int]$Timeout`, `[int[]]$PortList`, `[string]$OutDir`, `[switch]$SoftwareCheckEnabled`, `[array]$FlagRules`, `[string[]]$SoftwareFilters`, `[PSCredential]$Credential`, `[string]$DiscoveryCSVPath` |
| **Returns** | Nothing (all output is via Export functions) |
| **Phases** | 1: Host Discovery (or CSV load), 1b: OS Fingerprinting, 2: Software Version Check (conditional), 3: Vulnerability Scanning, 4: Output |

### Invoke-ListMode

| | |
|---|---|
| **Line** | ~3858 |
| **Purpose** | List scan mode orchestrator. Reads IPs from a file (or Discovery CSV), runs port discovery, OS fingerprinting, optional Software Version Check, plugin scanning, and output. Auto-detects Discovery CSV by checking the first line for the expected header. |
| **Parameters** | `[string]$HostFilePath`, `[array]$SelectedPlugins`, `[array]$SelectedOutputs`, `[int]$Threads`, `[int]$Timeout`, `[int[]]$PortList`, `[string]$OutDir`, `[switch]$SoftwareCheckEnabled`, `[array]$FlagRules`, `[string[]]$SoftwareFilters`, `[PSCredential]$Credential` |
| **Returns** | Nothing |
| **Phases** | Same as Scan mode, but Phase 1 is port discovery on provided hosts rather than CIDR expansion. |

### Invoke-ValidateMode

| | |
|---|---|
| **Line** | ~3949 |
| **Purpose** | Validate mode orchestrator. Loads an OpenVAS CSV, extracts unique IPs, runs host discovery and OS fingerprinting on those IPs, matches each finding to a validator plugin via `Find-Validator`, deduplicates test targets, runs plugin scans, and exports a validated CSV with appended result columns. |
| **Parameters** | `[string]$CSVPath`, `[array]$SelectedPlugins`, `[array]$SelectedOutputs`, `[int]$Threads`, `[int]$Timeout`, `[int[]]$PortList`, `[string]$OutDir`, `[PSCredential]$Credential` |
| **Returns** | Nothing |
| **Phases** | 1: Load OpenVAS CSV + Host Discovery + OS Fingerprinting, 2: Validate Findings, 3: Output (always includes Validated CSV). |

---

## Helper Functions (RunspacePool Injected)

These functions are defined as string blocks (`$script:HelperFunctionsString`, `$script:SoftwareHelperString`, `$script:VersionHelperString`) and injected into RunspacePool initial session state. They are duplicates of the main-thread functions listed above, with minor differences (e.g., hardcoded version string instead of `$script:Version`).

| Function | String Variable | Purpose |
|----------|----------------|---------|
| `Test-TCPConnect` | `$script:HelperFunctionsString` | TCP port reachability check inside RunspacePool threads. |
| `Send-TLSClientHello` | `$script:HelperFunctionsString` | Raw TLS ClientHello with specific cipher suite inside RunspacePool threads. |
| `Get-SSHKexAlgorithms` | `$script:HelperFunctionsString` | SSH banner + KEX_INIT parser inside RunspacePool threads. |
| `Get-OSFromBanner` | `$script:HelperFunctionsString` | SSH banner to OS name mapping inside RunspacePool threads. |
| `Compare-VersionStrings` | `$script:VersionHelperString` | Version comparison inside software check RunspacePool threads. |
| `Test-VersionAgainstRule` | `$script:VersionHelperString` | Flag rule evaluation inside software check RunspacePool threads. |
| `Get-VersionStatus` | `$script:VersionHelperString` | Human-readable version status inside software check RunspacePool threads. |
| `Get-SoftwareFromRegistry` | `$script:SoftwareHelperString` | Remote Registry enumeration inside software check RunspacePool threads. |
| `Get-SoftwareFromPSRemoting` | `$script:SoftwareHelperString` | PSRemoting enumeration inside software check RunspacePool threads. |
| `Get-SoftwareFromWMI` | `$script:SoftwareHelperString` | WMI enumeration inside software check RunspacePool threads. |

---

## Script-Level Variables

| Variable | Set At | Purpose |
|----------|--------|---------|
| `$script:Version` | Line 147 | Version string (`"1.0.0"`) |
| `$script:Build` | Line 148 | Build timestamp from file modification time |
| `$script:ConfigFile` | Line 149 | Path to `scottyscan.json` |
| `$script:Config` | Line 150 | Loaded config object (PSCustomObject) |
| `$script:Validators` | Line 151 | ArrayList of registered plugin validators |
| `$script:LogFile` | Line 152 | Path to current run's log file |
| `$script:Timestamp` | Line 153 | Run timestamp string (`"yyyyMMdd_HHmmss"`) for output file naming |
| `$script:TopPorts` | Line 157 | Array of ~100 common enterprise TCP port numbers |
| `$script:HelperFunctionsString` | Line 1693 | Here-string of network helper functions for RunspacePool injection |
| `$script:SoftwareHelperString` | Line 2178 | Here-string of software enumeration functions for RunspacePool injection |
| `$script:VersionHelperString` | Line 1968 | Here-string of version comparison functions for RunspacePool injection |
