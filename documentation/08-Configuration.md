# Configuration

This chapter documents the persistent configuration file (`scottyscan.json`), the complete CLI parameter reference, and how CLI parameters interact with stored configuration.

---

## scottyscan.json

### Overview

ScottyScan stores all user preferences in a JSON configuration file named `scottyscan.json`, located in the same directory as `ScottyScan.ps1`. This file is:

- **Auto-created** on first run if it does not exist
- **Updated automatically** after each interactive session (selections are saved back)
- **Human-editable** -- plain JSON that you can modify with any text editor
- **Deletable** -- remove it to reset all settings to defaults

The config file path is derived from `$PSScriptRoot`, so it always lives next to the script regardless of your working directory.

### Default Configuration

When `scottyscan.json` does not exist, ScottyScan initializes with these defaults:

```json
{
  "LastMode": "",
  "LastCIDRs": "",
  "LastCIDRFile": "",
  "LastHostFile": "",
  "LastInputCSV": "",
  "LastBrowseFolder": "",
  "CIDRInputHistory": [],
  "HostFileHistory": [],
  "InputCSVHistory": [],
  "FlagRuleFileHistory": [],
  "DefaultThreads": 20,
  "DefaultTimeoutMs": 5000,
  "DefaultPlugins": [],
  "DefaultOutputs": ["MasterCSV", "SummaryReport", "PerPluginCSV", "DiscoveryCSV"],
  "DefaultPorts": "plugin",
  "LastOutputDir": ".\\output_reports",
  "SavedFlagRules": [],
  "LastSoftwareFilter": ""
}
```

### Configuration Fields

#### Mode and Input History

| Field | Type | Description |
|-------|------|-------------|
| `LastMode` | string | Last selected mode: `"Scan"`, `"List"`, `"Validate"`, or `""` (none). Pre-selects the mode in the TUI on next run. |
| `LastCIDRs` | string | Legacy field. Last CIDR string entered (e.g., `"192.168.100.0/24,192.168.101.0/24"`). Superseded by `CIDRInputHistory`. |
| `LastCIDRFile` | string | Legacy field. Last CIDR file path. Used as fallback if `CIDRInputHistory` is empty. |
| `LastHostFile` | string | Legacy field. Last host file path. Used as fallback if `HostFileHistory` is empty. |
| `LastInputCSV` | string | Legacy field. Last OpenVAS CSV path. Used as fallback if `InputCSVHistory` is empty. |
| `LastBrowseFolder` | string | Last folder opened in the Windows file browse dialog. |
| `CIDRInputHistory` | string[] | Last 5 CIDR inputs (most recent first). Shown in the file prompt's history panel. |
| `HostFileHistory` | string[] | Last 5 host file paths (most recent first). |
| `InputCSVHistory` | string[] | Last 5 OpenVAS CSV paths (most recent first). |
| `FlagRuleFileHistory` | string[] | Last 5 flag rule file paths (most recent first). |

#### Scanning Defaults

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `DefaultThreads` | int | 20 | Number of concurrent threads for discovery and plugin scanning. |
| `DefaultTimeoutMs` | int | 5000 | TCP connect timeout per test in milliseconds. |
| `DefaultPorts` | string | `"plugin"` | Port scanning scope. Values: `"all"` (1-65535), `"top100"` (top 100 enterprise ports), `"plugin"` (union of ports declared by selected plugins), or a comma-separated port list (e.g., `"22,80,443,3389"`). |
| `DefaultPlugins` | string[] | `[]` | Plugin names to pre-select in the TUI. Empty array means all plugins are selected by default. Include `"__SoftwareVersionCheck__"` to pre-select the Software Version Check feature. |

#### Output Defaults

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `DefaultOutputs` | string[] | `["MasterCSV", "SummaryReport", "PerPluginCSV", "DiscoveryCSV"]` | Output types to pre-select in the TUI. |
| `LastOutputDir` | string | `".\\output_reports"` | Output directory path. Relative paths are resolved from `$PSScriptRoot`. |

#### Software Version Check

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `SavedFlagRules` | object[] | `[]` | Saved flag rules for the Software Version Check. Each entry has `Pattern`, `VersionRule`, and `Label` fields. Persisted when the user enters or loads rules through the TUI. |
| `LastSoftwareFilter` | string | `""` | Last software filter pattern string entered in the TUI. |

### Input History System

ScottyScan maintains a rolling history of the last 5 entries for each input type. The history system:

- **Deduplicates** entries -- if you re-enter a value that already exists in history, it moves to the front instead of creating a duplicate
- **Caps at 5 entries** -- the oldest entry is dropped when a 6th is added
- **Most-recent-first** ordering -- the newest entry is always at index 0
- **Falls back to legacy fields** -- if the history array is empty, ScottyScan checks the legacy `Last*` fields for backwards compatibility with older config files

History entries are displayed in the left panel of the two-panel file input TUI, so you can quickly re-select previous inputs with arrow keys.

### SavedFlagRules Format

Flag rules are stored as an array of objects:

```json
{
  "SavedFlagRules": [
    {
      "Pattern": "*7-zip*",
      "VersionRule": "LT24.9.0",
      "Label": "CVE-2024-11477"
    },
    {
      "Pattern": "*notepad*",
      "VersionRule": "LT8.9.1",
      "Label": "CVE-2025-15556"
    },
    {
      "Pattern": "*putty*",
      "VersionRule": "LT0.82",
      "Label": "CVE-2024-31497"
    }
  ]
}
```

- **Pattern:** Wildcard pattern matched against software display names (e.g., `*7-zip*` matches "7-Zip 23.01 (x64)")
- **VersionRule:** Version comparison using a text operator prefix. Operators: `LT` (less than), `LE` (less than or equal), `GT` (greater than), `GE` (greater than or equal), `EQ` (equal), `NE` (not equal), `*` (match any version, text-only flag)
- **Label:** Descriptive label for the rule, typically a CVE identifier

In the interactive TUI (Step 3: Flag Rules Configuration), the user can:
- Load rules from a CSV file
- Enter rules manually
- Use previously saved rules (from this config field)
- Skip flag rules entirely

When rules are entered or loaded, they are saved to `SavedFlagRules` for reuse on subsequent runs.

---

## CLI Parameter Reference

ScottyScan accepts 22 parameters. When launched without any mode parameter (`-Scan`, `-List`, `-Validate`), it enters interactive mode and displays the TUI.

### Mode Selection

These three parameters are mutually exclusive (enforced by PowerShell parameter sets). Omit all three for interactive mode.

| Parameter | Type | Parameter Set | Description |
|-----------|------|---------------|-------------|
| `-Scan` | switch | Scan | Network discovery mode. Discovers hosts on CIDR ranges using ping and TCP probes, fingerprints OS, then runs selected plugins against discovered hosts. |
| `-List` | switch | List | Host list mode. Reads IPs or hostnames from a file, performs port discovery on each host, then runs selected plugins. Skips CIDR expansion and ping sweep. |
| `-Validate` | switch | Validate | Validation mode. Reads an OpenVAS CSV export, matches each finding to a plugin by NVT name, re-tests each specific host+port+vulnerability combination, and produces a validated CSV with updated status. |

### Input Parameters

| Parameter | Type | Modes | Description |
|-----------|------|-------|-------------|
| `-CIDRs` | string | Scan | Comma-separated CIDR ranges for network discovery. Example: `"192.168.100.0/24,192.168.101.0/24"` |
| `-CIDRFile` | string | Scan | Path to a text file with one CIDR range per line. Alternative to `-CIDRs` for large or complex range lists. |
| `-HostFile` | string | List | Path to a text file with one IP address or hostname per line. ScottyScan auto-detects if the file is a Discovery CSV (by checking the header line) and loads it accordingly. |
| `-InputCSV` | string | Validate | Path to an OpenVAS CSV export file. See [09-OpenVAS-Integration.md](09-OpenVAS-Integration.md) for the expected CSV format. |

### Plugin Control

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Plugins` | string | All available | Comma-separated list of plugin names to enable. Example: `"DHEater-TLS,DHEater-SSH"`. Use `"SoftwareVersionCheck"` to enable the Software Version Check feature alongside or instead of vulnerability plugins. When omitted, all loaded plugins are used. |
| `-PluginDir` | string | `plugins/` | Path to the directory containing plugin `.ps1` files. Defaults to the `plugins/` subdirectory next to `ScottyScan.ps1`. |

### Software Version Check -- Flag Rules

These parameters configure the flag rules engine for the Software Version Check feature. They are only relevant when `SoftwareVersionCheck` is included in the `-Plugins` parameter.

| Parameter | Type | Description |
|-----------|------|-------------|
| `-FlagFilter` | string | Comma-separated wildcard patterns for software name matching. Each position corresponds to the same position in `-FlagVersion` and `-FlagLabel`. Example: `"*notepad*,*7-zip*,*putty*"` |
| `-FlagVersion` | string | Comma-separated version threshold rules. Text operators: `LT`, `LE`, `GT`, `GE`, `EQ`, `NE`, `*` (any version). Example: `"LT8.9.1,LT24.9.0,LT0.82"` |
| `-FlagLabel` | string | Comma-separated labels for each flag rule. Typically CVE identifiers. Example: `"CVE-2025-15556,CVE-2024-11477,CVE-2024-31497"` |
| `-FlagFilterFile` | string | Path to a CSV rule file. Each line has the format `pattern,versionrule,label`. File-format version operators use symbols: `<`, `<=`, `>`, `>=`, `=`, `!=`, `*`. This parameter replaces the three inline parameters above. |

### Software Inventory Filtering

| Parameter | Type | Description |
|-----------|------|-------------|
| `-SoftwareFilter` | string | Comma-separated wildcard patterns to filter the software inventory output. Only software matching these patterns is included in the inventory CSV. When omitted, flag rule patterns are used as implicit filters. |
| `-SoftwareFilterFile` | string | Path to a text file with one wildcard pattern per line. Alternative to `-SoftwareFilter` for large filter lists. |

### Execution Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-MaxThreads` | int | 20 (or from config) | Number of concurrent threads for host discovery and plugin scanning. Both phases use RunspacePool parallelism. Higher values increase scan speed but also network load. |
| `-TimeoutMs` | int | 5000 (or from config) | TCP connect timeout per test in milliseconds. Used for port scanning during discovery and for plugin test connections. Lower values speed up scans but may miss slow-responding hosts. |
| `-Ports` | string | `"plugin"` (or from config) | Port scanning scope for the discovery phase. Values: `"all"` (1-65535 with priority ordering), `"top100"` (top 100 enterprise ports), `"plugin"` (union of ports declared by selected plugins), or a comma-separated list of port numbers. |
| `-OutputDir` | string | `.\output_reports` (or from config) | Directory for all output files. Relative paths are resolved from `$PSScriptRoot`. Created automatically if it does not exist. |
| `-NoMenu` | switch | Off | Skip all interactive menus. Requires sufficient CLI parameters to define the scan (mode, input, etc.). Required for scripted and scheduled execution. |
| `-Credential` | PSCredential | None | Credential object for remote Windows access (WMI, PSRemoting, Remote Registry). Required for the Software Version Check feature when scanning non-domain-joined hosts or when the current user lacks remote admin rights. Create with `Get-Credential` or `[PSCredential]::new()`. |

---

## Interaction Between CLI and Config

ScottyScan uses a layered configuration model. Values are resolved in this priority order:

1. **CLI parameter** (highest priority) -- explicitly provided on the command line
2. **Config file value** -- loaded from `scottyscan.json`
3. **Built-in default** (lowest priority) -- hardcoded in the script

### Resolution Examples

```powershell
# Threads: CLI wins over config
$threads = if ($MaxThreads -gt 0) { $MaxThreads }
           elseif ($script:Config.DefaultThreads) { $script:Config.DefaultThreads }
           else { 20 }

# Timeout: CLI wins over config
$timeout = if ($TimeoutMs -gt 0) { $TimeoutMs }
           elseif ($script:Config.DefaultTimeoutMs) { $script:Config.DefaultTimeoutMs }
           else { 5000 }

# Ports: CLI wins over config
$portStr = if ($Ports) { $Ports }
           elseif ($script:Config.DefaultPorts) { $script:Config.DefaultPorts }
           else { "plugin" }

# Output directory: CLI wins over config
$outDir = if ($OutputDir) { $OutputDir }
          else { $script:Config.LastOutputDir }
```

### Interactive Mode Behavior

In interactive mode (no `-NoMenu` flag):

1. **Config values pre-populate the TUI.** When the TUI displays a menu, the selections from the previous run are pre-checked. For example, if you selected `DHEater-TLS` and `SSH1-Deprecated` last time, those plugins will have checkmarks when the plugin menu appears.

2. **Changes are saved back to config.** After each TUI step, the user's selection is written to the config object via `Update-ConfigValue`. At the end of the interactive flow (after the confirmation screen), `Save-Config` writes the entire config object to `scottyscan.json`.

3. **History entries accumulate.** Every input file path and CIDR string is pushed to the appropriate history array, creating a most-recently-used list that appears in future runs.

### Non-Interactive Mode Behavior

When `-NoMenu` is specified:

1. **CLI parameters are required** for mode, input, and any other settings that differ from defaults.
2. **Config values fill gaps.** Any parameter not specified on the CLI falls back to the config file value, then to the built-in default. For example, if you omit `-MaxThreads`, the thread count comes from `DefaultThreads` in the config file (or 20 if the config does not have a value).
3. **Config is still saved.** After a non-interactive run, the selections are saved back to `scottyscan.json`, so the next interactive run inherits them.

### Resetting Configuration

To reset all settings to defaults, delete the config file:

```powershell
Remove-Item .\scottyscan.json
```

ScottyScan will recreate it with default values on the next run.

---

## Port Configuration Details

The `-Ports` parameter (and `DefaultPorts` config field) controls which TCP ports are probed during the host discovery phase. This setting affects discovery only -- plugin scanning is always scoped to each plugin's declared `ScanPorts`.

### Port Options

| Value | Ports Scanned | Description |
|-------|---------------|-------------|
| `"all"` | 1-65535 | Full TCP port sweep. Uses priority ordering: top 100 enterprise ports and plugin-declared ports are scanned first, then the remaining ports. |
| `"top100"` | ~100 ports | Common enterprise service ports: 21, 22, 23, 25, 53, 80, 88, 135, 139, 443, 445, 993, 1433, 3306, 3389, 5432, 5985, 8080, 8443, 9090, and others. |
| `"plugin"` | Varies | Union of all ports declared by the selected plugins' `ScanPorts` arrays. Falls back to all 65535 if no plugins declare specific ports. |
| `"custom"` (TUI) | User-specified | In the TUI, selecting "Custom port list" prompts for a comma-separated list of port numbers. |
| `"22,80,443,3389"` | As specified | CLI: a comma-separated list of port numbers is parsed directly. |

### Automatic Management Port Restriction

When only the Software Version Check is selected (no vulnerability plugins), and no explicit port configuration is provided, ScottyScan automatically restricts port scanning to management ports only:

- **135** -- WMI/DCOM
- **445** -- Remote Registry (SMB)
- **5985** -- PSRemoting/WinRM (HTTP)
- **5986** -- PSRemoting/WinRM (HTTPS)

This avoids a full 65535-port scan when the only feature being used needs just these four ports.

### Plugin Port Merging

Regardless of the port option selected, plugin-declared `ScanPorts` are always merged into the port list. This ensures that discovery finds the ports each plugin needs to test, even when using `"top100"` or a custom list that might not include them.

---

## Example: Complete CLI Invocation

This example demonstrates a fully parameterized non-interactive run:

```powershell
.\ScottyScan.ps1 -List `
    -HostFile "C:\input_files\targets.txt" `
    -Plugins "SoftwareVersionCheck,DHEater-TLS,DHEater-SSH,SSH1-Deprecated" `
    -FlagFilter "*notepad*,*7-zip*" `
    -FlagVersion "LT8.9.1,LT24.9.0" `
    -FlagLabel "CVE-2025-15556,CVE-2024-11477" `
    -MaxThreads 30 `
    -TimeoutMs 3000 `
    -Ports "top100" `
    -OutputDir "C:\Reports\February" `
    -Credential (Get-Credential) `
    -NoMenu
```

This command:
1. Runs in List mode, reading hosts from `targets.txt`
2. Enables Software Version Check plus three vulnerability plugins
3. Flags Notepad++ older than 8.9.1 and 7-Zip older than 24.9.0
4. Uses 30 threads with a 3-second timeout
5. Scans only the top 100 enterprise ports during discovery
6. Writes output to `C:\Reports\February`
7. Prompts for credentials (for Software Version Check remote access)
8. Skips the interactive TUI entirely

---

## Next Steps

- **[07-Output-and-Reporting.md](07-Output-and-Reporting.md)** -- What output files are generated and their formats
- **[06-Software-Version-Check.md](06-Software-Version-Check.md)** -- Flag rules, version comparison operators, enumeration chain
- **[03-Interactive-TUI.md](03-Interactive-TUI.md)** -- How the TUI menus work and how config values pre-populate them
- **[01-Getting-Started.md](01-Getting-Started.md)** -- Quick CLI examples for common use cases
