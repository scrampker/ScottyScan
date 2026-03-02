# 06 - Software Version Check

## Overview

The Software Version Check engine inventories installed software on Windows hosts and flags versions that match user-defined vulnerability or compliance rules. It was merged from the legacy `Discover-And-Inventory.ps1` script and operates as a core feature of ScottyScan rather than as a plugin.

Key characteristics:

- **Appears in the plugin selection menu** as "Software Version Check" (the first item in the list).
- **Internal identifier**: `__SoftwareVersionCheck__` (used to distinguish it from actual plugins in the selection logic).
- **Runs as a separate phase** between host discovery and plugin scanning.
- **Not a plugin** -- it does not use `Register-Validator` or the `Invoke-PluginScan` engine. Instead, it has its own execution function (`Invoke-SoftwareCheck`, line ~3171) and output functions (`Export-SoftwareOutputs`, line ~3392).
- **Windows-only**: Automatically filters to hosts identified as Windows (by OS fingerprint or by having port 445 open). Non-Windows hosts are skipped.

---

## Execution Flow in Scan/List Modes

When the Software Version Check is selected alongside vulnerability plugins, the scan execution proceeds through four phases:

```
Phase 1:  Host Discovery
          - CIDR expansion (Scan mode) or file loading (List mode)
          - Batched async TCP port scanning
          - Reverse DNS lookup
          - TTL-based OS guessing

Phase 1b: OS Fingerprinting
          - CIM/WMI queries for Windows
          - SSH banner parsing for Linux/ESXi
          - Port heuristics fallback

Phase 2:  Software Version Check (conditional -- only if selected)
          - Remote software enumeration on Windows hosts
          - Flag rule evaluation
          - Software-specific output generation

Phase 3:  Vulnerability Scanning (plugins)
          - Plugin test matrix construction
          - RunspacePool parallel testing
          - Real-time result output

Phase 4:  Output Generation
          - Master CSV (plugin + software findings merged)
          - Summary report
          - Per-plugin CSVs
          - Discovery CSV
          - Software inventory and flagged CSVs (from Phase 2)
```

If the Software Version Check is **not** selected, Phase 2 is skipped entirely and the execution proceeds directly from OS fingerprinting to plugin scanning.

---

## Remote Software Enumeration

The `Invoke-SoftwareCheck` function dispatches one RunspacePool job per Windows host. Each job attempts to enumerate installed software using a three-method fallback chain. If one method returns results, the subsequent methods are not attempted.

### Method 1: Remote Registry (Fastest)

**Function**: `Get-SoftwareFromRegistry` (line ~2046)

Reads the Windows registry remotely using `[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey()`:

- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` -- 64-bit applications
- `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` -- 32-bit applications on 64-bit systems

For each registry subkey, it reads `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, `InstallLocation`, and determines the architecture from which registry path the entry was found in.

**Requirements**:
- The Remote Registry service must be running on the target host.
- Port 445 (SMB) must be reachable.
- The scanning account must have administrative privileges on the target.

**Advantages**: Fastest method. Does not require WinRM or WMI. Minimal impact on the target host.

### Method 2: PSRemoting (Fallback)

**Function**: `Get-SoftwareFromPSRemoting` (line ~2089)

Uses `Invoke-Command` to execute a registry enumeration script block on the remote host via PowerShell Remoting (WinRM). The script block reads the same Uninstall registry paths locally on the target.

**Requirements**:
- WinRM must be enabled on the target (ports 5985 or 5986).
- PowerShell Remoting must be configured (typically via `Enable-PSRemoting`).
- Credentials with administrative access (passed via `-Credential` parameter).

**Advantages**: Works when Remote Registry service is not available. More reliable in locked-down environments where SMB is restricted but WinRM is allowed.

### Method 3: WMI Win32_Product (Last Resort)

**Function**: `Get-SoftwareFromWMI` (line ~2145)

Queries the `Win32_Product` WMI class via `Get-CimInstance`. This is the most compatible method but has significant drawbacks.

**Requirements**:
- WMI/DCOM access via port 135.
- Credentials with administrative access.

**Drawbacks**:
- **Slow**: Can take several minutes per host, especially with many installed applications.
- **Side effects**: Querying `Win32_Product` can trigger MSI reconfiguration/repair on the target host, which may cause unexpected service restarts or configuration changes.
- **Incomplete**: Only lists MSI-installed applications. Software installed via other mechanisms (xcopy, zip extract, MSIX) will not appear.

Use only as a last resort when neither Remote Registry nor PSRemoting is available.

### Deduplication

After enumeration completes (regardless of which method succeeded), results are deduplicated by `Name` and `Version` using `Sort-Object Name, Version -Unique`. This prevents duplicate entries when the same application appears in both the 64-bit and 32-bit registry paths with identical names and versions.

---

## Flag Rules Engine

Flag rules define which software should be flagged based on a name pattern and an optional version condition. They are the mechanism for identifying outdated, vulnerable, or non-compliant software.

### Rule Structure

Each flag rule has three fields:

| Field | Description | Example |
|-------|-------------|---------|
| `Pattern` | Wildcard pattern matched against the software DisplayName | `*7-zip*` |
| `VersionRule` | Version comparison expression | `LT24.9.0` or `<24.9.0` |
| `Label` | Human-readable identifier (typically a CVE or policy reference) | `CVE-2024-11477` |

A rule matches when: (1) the software name matches the wildcard pattern, AND (2) the installed version satisfies the version comparison expression.

### Specifying Rules via CLI

Three comma-delimited parameters with positional correspondence:

```powershell
.\ScottyScan.ps1 -List -HostFile .\hosts.txt `
    -FlagFilter "*notepad*,*7-zip*" `
    -FlagVersion "LT8.9.1,LT24.9.0" `
    -FlagLabel "CVE-2025-15556,CVE-2024-11477"
```

This creates two rules:
1. Flag any software matching `*notepad*` where the version is less than 8.9.1, labeled CVE-2025-15556.
2. Flag any software matching `*7-zip*` where the version is less than 24.9.0, labeled CVE-2024-11477.

If fewer version rules or labels are provided than patterns, the missing entries default to `*` (flag any version) and empty string (no label), respectively.

### Specifying Rules via File

A CSV file passed with `-FlagFilterFile`:

```csv
pattern,versionrule,label
*notepad*,<8.9.1,CVE-2025-15556
*7-zip*,<24.9.0,CVE-2024-11477
*adobe reader*,<2024.004.20220,EOL Version
*java*,*,Compliance: Java inventory
```

File format notes:
- Header line (`pattern,versionrule,label`) is optional but recommended. Lines starting with `#` are treated as comments.
- The version rule uses symbol operators (`<`, `<=`, `>`, `>=`, `=`, `!=`, `*`) rather than text operators.
- Lines with fewer than 2 columns are skipped.
- If the label column contains commas, everything from the third field onward is joined and used as the label.

The `Import-FlagRules` function (line ~1917) handles both CLI parameter parsing and file loading. If both `-FlagFilter` and `-FlagFilterFile` are specified, the rules from both sources are combined.

---

## Version Operators

Flag rules support two equivalent sets of version comparison operators.

### Text Operators (CLI Format)

Used when specifying rules via `-FlagVersion` on the command line:

| Operator | Meaning | Example | Flags When |
|----------|---------|---------|------------|
| `LT` | Less than | `LT8.9.1` | Installed version < 8.9.1 |
| `LE` | Less than or equal | `LE8.8.8` | Installed version <= 8.8.8 |
| `GT` | Greater than | `GT1.0` | Installed version > 1.0 |
| `GE` | Greater than or equal | `GE2.0` | Installed version >= 2.0 |
| `EQ` | Equal | `EQ5.5.1` | Installed version = 5.5.1 |
| `NE` | Not equal | `NE8.9.1` | Installed version != 8.9.1 |
| `*` | Any version (text match only) | `*` | Always flags if name matches |

### Symbol Operators (File Format)

Used when specifying rules in a `-FlagFilterFile` CSV:

| Operator | Meaning |
|----------|---------|
| `<` | Less than |
| `<=` | Less than or equal |
| `>` | Greater than |
| `>=` | Greater than or equal |
| `=` | Equal |
| `!=` | Not equal |
| `*` | Any version |

### Version Comparison Logic

Version comparison is handled by `Compare-VersionStrings` (line ~1810), which performs dotted-integer comparison:

1. Both version strings are split on `.` into arrays of integers.
2. Arrays are compared element by element from left to right.
3. If one array is shorter, missing elements are treated as `0`.
4. Returns `-1` (current < target), `0` (equal), or `1` (current > target).

Examples:
- `24.9.0` vs `23.01` -- result: 1 (24 > 23, so current is greater)
- `8.8.0` vs `8.9.1` -- result: -1 (8=8, then 8 < 9, so current is less)
- `1.0` vs `1.0.0` -- result: 0 (equal, missing element treated as 0)

`Test-VersionAgainstRule` (line ~1838) parses the operator from the rule string and applies it to the comparison result. A return value of `$true` means the software IS flagged (i.e., vulnerable or matching the rule condition).

Special cases:
- If the rule is `*`, the software is always flagged regardless of version.
- If the installed version is empty or null, the software is flagged (unknown version is assumed vulnerable).
- If no operator prefix is recognized, the rule is treated as a "less than" comparison (the most common remediation case).

---

## Interactive Flag Rules Configuration (TUI Step 3)

When the Software Version Check is selected in the plugin menu, the TUI state machine advances to a flag rules configuration step before the credential prompt. This step offers four options:

### 1. Load from File

Opens the file prompt TUI (two-panel layout with history on the left and browse/type actions on the right). The user selects or types the path to a `flag_rules.csv` file. The file is parsed by `Import-FlagRules` and the rules are displayed for confirmation.

### 2. Enter Manually

Prompts the user to type flag patterns, version rules, and labels inline. This creates rules on the fly without needing a file.

### 3. Use Saved Rules

Loads previously saved flag rules from `scottyscan.json` under the `SavedFlagRules` key. Rules are automatically saved to the config file whenever they are used, so this option restores the rules from the last run.

### 4. Skip

Runs the software check without any flag rules. Software will still be inventoried and exported, but nothing will be flagged as vulnerable. The output will contain `SoftwareInventory_ALL_*.csv` but no `FLAGGED_*` files.

---

## Credential Handling (TUI Step 4)

When the Software Version Check is selected, the TUI prompts for Windows credentials after flag rules configuration.

### Credential Prompt

- Accepts `Domain\Username` format (e.g., `INFOWERKS\admin` or `.\Administrator`).
- Password is entered securely (masked input).
- A `[PSCredential]` object is created from the input.

### How Credentials Are Used

The credential object is passed to all three enumeration methods:

| Method | Credential Usage |
|--------|-----------------|
| Remote Registry | Not directly used (relies on the scanning account's implicit access via SMB) |
| PSRemoting | Passed as `-Credential` to `Invoke-Command` |
| WMI | Passed as `-Credential` to `Get-CimInstance` |

If no credentials are provided (the user skips the prompt), the enumeration runs under the implicit security context of the PowerShell session. This works in domain environments where the scanning workstation is domain-joined and the operator has administrative privileges on the targets.

The same credential object is also passed to the OS fingerprinting phase (`Invoke-OSFingerprint`) for CIM/WMI queries.

---

## Output Files

The Software Version Check produces its own set of output files via `Export-SoftwareOutputs` (line ~3392), separate from the main plugin output pipeline. All files are written to the output directory with a timestamp suffix.

### SoftwareInventory_ALL_[timestamp].csv

Complete software inventory across all scanned Windows hosts. Columns:

```
ComputerName, Name, Version, Publisher, InstallDate, InstallPath, Architecture, Source
```

When flag rules are defined, this CSV is filtered to only include software matching the flag rule patterns (or explicit software filters, if provided). This prevents the file from containing thousands of irrelevant entries.

### SoftwareInventory_FILTERED_[timestamp].csv

Only generated when explicit software filters are provided separately from flag rules. Contains the subset of the inventory matching those filters.

### FLAGGED_ALL_TARGETS_[timestamp].csv

Master list of all flagged software findings across all hosts. Columns:

```
ComputerName, Hostname, SoftwareName, Version, Architecture, InstallPath, FlagRule, FlagPattern, FlagLabel, Status
```

Sorted by flag pattern, then computer name, then software name.

### FLAGGED_ALL_IPs_[timestamp].txt

Simple newline-delimited list of unique IP addresses that have at least one flagged software finding. Designed for feeding into deployment tools, SCCM collections, or remediation scripts.

### FLAGGED_[pattern]_TARGETS_[timestamp].csv

Per-rule flagged target CSVs. One file is generated for each unique flag rule pattern+version combination. The `[pattern]` portion of the filename is derived from the flag pattern with special characters removed.

For example, a flag rule with pattern `*7-zip*` would produce `FLAGGED_7-zip_TARGETS_[timestamp].csv`.

### FLAGGED_[pattern]_IPs_[timestamp].txt

Per-rule IP lists. Same as the master IP list but filtered to a single flag rule. Useful when different teams are responsible for remediating different software.

---

## Integration with Main Results

Software Version Check findings are merged into the main results stream so they appear alongside plugin findings in the unified output files (Master CSV and Summary Report).

### Finding Format

Each flagged software entry is converted to the standard finding format used by `Invoke-PluginScan`:

```powershell
@{
    IP         = "192.168.100.5"
    Port       = "0"                          # Sentinel value (not port-specific)
    Hostname   = "dc01.domain.local"
    OS         = "Windows Server 2019 ..."
    PluginName = "SoftwareVersionCheck"
    Result     = "Vulnerable"
    Detail     = "7-Zip 23.01 (x64) v23.01 -- *** FLAGGED *** (v23.01 matches rule: <24.9.0) [CVE-2024-11477]"
}
```

Key points:
- **Port** is always `0` because software version findings are host-level, not port-level.
- **PluginName** is always `SoftwareVersionCheck`.
- **Result** is always `Vulnerable` (only flagged entries are emitted as findings; non-flagged software is recorded in the inventory CSVs only).
- **Detail** includes the software name, installed version, the version rule, and the flag label.

### Where Findings Appear

The merged findings appear in:

- **Master CSV** (`ScottyScan_Master_[timestamp].csv`): Interleaved with plugin findings, sortable by PluginName to isolate software findings.
- **Summary Report** (`ScottyScan_Summary_[timestamp].txt`): Listed under the SoftwareVersionCheck section with counts and details.
- **Per-Plugin CSV** (`SoftwareVersionCheck_[timestamp].csv`): A dedicated CSV containing only the software version check findings, generated alongside per-plugin CSVs for DHEater-TLS, SSH1-Deprecated, etc.

---

## RunspacePool Execution Details

The `Invoke-SoftwareCheck` function uses a RunspacePool capped at `[Math]::Min($MaxThreads, 10)` concurrent jobs. The cap of 10 is lower than the discovery phase cap because each software enumeration job can be resource-intensive on the target host (especially the WMI fallback).

### Helper Function Injection

Because RunspacePool jobs execute in isolated runspaces without access to the parent session's functions, the software enumeration and version comparison functions are injected as strings:

- `$script:SoftwareHelperString` -- stringified versions of `Get-SoftwareFromRegistry`, `Get-SoftwareFromPSRemoting`, and `Get-SoftwareFromWMI`.
- `$script:VersionHelperString` -- stringified versions of `Compare-VersionStrings`, `Test-VersionAgainstRule`, and `Get-VersionStatus`.

Flag rules and software filters are serialized to JSON via `ConvertTo-Json` and deserialized inside the runspace via `ConvertFrom-Json`.

### Real-Time Output

As jobs complete, results are printed to the console in real time:

- **Inventory results**: `[1/14] 192.168.100.5 (dc01.domain.local) -- 147 apps via Registry` (gray text)
- **Flagged findings**: `*** FLAGGED *** 192.168.100.5 -- 7-Zip 23.01 (x64) v23.01 (<24.9.0) [CVE-2024-11477]` (red text)

A spinner with elapsed time and completion count displays while jobs are still running.
