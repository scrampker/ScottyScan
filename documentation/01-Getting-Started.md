# Getting Started with ScottyScan

This chapter covers prerequisites, project layout, and how to run ScottyScan for the first time -- both interactively and from the command line.

---

## Prerequisites

### PowerShell

ScottyScan requires **PowerShell 5.1 or later**. Windows PowerShell 5.1 ships with Windows 10 and Windows Server 2016+. PowerShell 7+ (pwsh) is also supported.

Check your version:

```powershell
$PSVersionTable.PSVersion
```

### Operating System

ScottyScan is designed to run on **Windows**. It uses Windows-specific APIs including:

- `[Console]::SetCursorPosition` and `[Console]::ReadKey` for the interactive TUI
- Remote Registry, PSRemoting (WinRM), and WMI/CIM for the Software Version Check feature
- `[System.Net.Sockets.TcpClient]` for network probes

### Privileges

- **Basic scanning** (DHEater, SSH1, port discovery): No special privileges required. Any user can run network probes.
- **Software Version Check**: Requires **administrator privileges** and appropriate credentials for remote hosts. Domain admin or equivalent is needed for Remote Registry, PSRemoting, and WMI access to target Windows machines.
- **Scan mode with ICMP ping**: Sending ICMP echo requests may require running PowerShell as Administrator depending on your environment's firewall rules.

### Network Access

ScottyScan makes outbound TCP connections to target hosts. Ensure your workstation's firewall and any network firewalls allow:

- Outbound TCP to all ports on target hosts (for port scanning)
- ICMP echo (for host discovery ping in Scan mode)
- TCP 135, 445, 5985, 5986 to target Windows hosts (for Software Version Check)

---

## Project Structure

```
ScottyScan/
    ScottyScan.ps1              Main script (~4800 lines)
    scottyscan.json             Auto-created config file (persistent state)
    CLAUDE.md                   AI-context companion document
    README.md                   Project overview
    dev-watch.ps1               File watcher for live-reload during development

    plugins/
        DHEater-TLS.ps1         D(HE)ater on SSL/TLS (CVE-2002-20001)
        DHEater-SSH.ps1         D(HE)ater on SSH
        SSH1-Deprecated.ps1     Deprecated SSH-1 protocol detection
        7Zip-Version.ps1        Outdated 7-Zip (remote registry/WMI)
        _PluginTemplate.ps1     Template for creating new plugins

    documentation/
        00-Index.md             Documentation home / table of contents
        01-Getting-Started.md   This file
        02-Modes-of-Operation.md through 13-Environment-Research.md
        ScottyScan-Architecture-Spec.md   Platform architecture spec

    legacy/
        Discover-And-Inventory.ps1   Previous standalone script (features being merged)

    openvas_legacy_research/
        Greenbone_CE_Setup_Guide.md  GCE installation and configuration
        csv_analysis.md              OpenVAS CSV format analysis
        (other research documents)

    input_files/                Host lists, CIDR files, OpenVAS CSVs (gitignored)
    output_reports/             All scan output (gitignored)
        logs/                   Verbose per-run log files
```

### Key Files

| File | Purpose |
|------|---------|
| `ScottyScan.ps1` | The entire scanner in one file. All functions, TUI, scanning engine, and output generation. |
| `scottyscan.json` | Persistent configuration. Auto-created on first run. Stores last-used mode, plugins, threads, timeout, input file history, flag rules, and output preferences. |
| `plugins/*.ps1` | Vulnerability check plugins. Each file calls `Register-Validator` with a hashtable defining the check. Files starting with `_` are skipped by the plugin loader. |
| `dev-watch.ps1` | Development helper that watches `ScottyScan.ps1` for changes and re-parses it, reporting syntax errors instantly. |

---

## Running ScottyScan for the First Time

### Interactive Mode (Recommended for First Run)

Launch ScottyScan with no parameters to enter the interactive TUI:

```powershell
.\ScottyScan.ps1
```

The menu system will walk you through every configuration step:

1. **Mode selection** -- Choose Scan, List, or Validate
2. **Plugin selection** -- Check which vulnerability plugins to run (plus Software Version Check)
3. **Flag rules** -- Configure software version flagging (only if Software Version Check is selected)
4. **Credentials** -- Enter credentials for remote Windows access (only if Software Version Check is selected)
5. **Output selection** -- Choose which output files to generate
6. **Settings** -- Configure thread count, timeout, and port scanning scope
7. **Input** -- Provide CIDR ranges, host file, or OpenVAS CSV (depending on mode)
8. **Confirmation** -- Review all settings, then press Enter to execute or Escape to go back

Use arrow keys to navigate, Spacebar to toggle selections, Enter to confirm, and Escape to go back to the previous step. See [03-Interactive-TUI.md](03-Interactive-TUI.md) for full keyboard controls.

### What Happens on First Run

- ScottyScan loads all plugins from the `plugins/` directory
- If `scottyscan.json` does not exist, it is created with default settings
- The interactive TUI launches with sensible defaults pre-selected
- After the scan completes, output files are written to `output_reports/`

---

## Running with CLI Parameters

For scripted or scheduled execution, pass all configuration as command-line parameters and include the `-NoMenu` flag to skip the interactive TUI.

### Example 1: Interactive Mode

```powershell
.\ScottyScan.ps1
```

Launches the full interactive menu. No parameters required. All configuration happens through the TUI.

### Example 2: Network Scan (Scan Mode)

```powershell
.\ScottyScan.ps1 -Scan -CIDRs "192.168.100.0/24,192.168.101.0/24" -NoMenu
```

Discovers hosts on the specified CIDR ranges using ping and TCP probes, fingerprints their operating systems, then runs all available plugins against discovered hosts. Use `-CIDRs` for inline CIDR notation or `-CIDRFile` for a text file with one CIDR per line.

### Example 3: List Scan (List Mode)

```powershell
.\ScottyScan.ps1 -List -HostFile .\targets.txt -Plugins "DHEater-TLS,DHEater-SSH" -NoMenu
```

Reads IP addresses or hostnames from `targets.txt` (one per line), performs port discovery on each host, then runs only the specified plugins. List mode skips the CIDR expansion and ping sweep -- it goes straight to port scanning the provided hosts.

### Example 4: Validate OpenVAS Findings (Validate Mode)

```powershell
.\ScottyScan.ps1 -Validate -InputCSV .\findings.csv -NoMenu
```

Reads an OpenVAS CSV export, matches each finding's `nvt_name` to a registered plugin using the plugin's `NVTPattern` regex, then re-tests each specific host+port+vulnerability combination. Produces a validated CSV with updated status (Remediated, Confirmed Vulnerable, etc.).

### Example 5: List Scan with Software Version Check and Flag Rules

```powershell
.\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu `
    -Plugins "SoftwareVersionCheck,DHEater-TLS" `
    -FlagFilter "*notepad*,*7-zip*" -FlagVersion "LT8.9.1,LT24.9.0" `
    -FlagLabel "CVE-2025-15556,CVE-2024-11477"
```

Runs both vulnerability plugins and the software version check engine. Flag rules define which software to flag: any Notepad++ older than 8.9.1 is flagged as CVE-2025-15556, and any 7-Zip older than 24.9.0 is flagged as CVE-2024-11477.

### Example 6: Flag Rules from a CSV File

```powershell
.\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu `
    -Plugins "SoftwareVersionCheck" -FlagFilterFile .\flag_rules.csv
```

Loads flag rules from a CSV file instead of inline parameters. The file format is one rule per line: `pattern,versionrule,label`. For example:

```
*notepad*,<8.9.1,CVE-2025-15556
*7-zip*,<24.9.0,CVE-2024-11477
*putty*,<0.82,CVE-2024-31497
```

---

## CLI Parameter Reference (Quick)

The full parameter reference is in [08-Configuration.md](08-Configuration.md). Here is a summary of the most common parameters:

### Mode Selection (mutually exclusive)

| Parameter | Description |
|-----------|-------------|
| `-Scan` | Network discovery + vulnerability scanning |
| `-List` | Scan hosts from a file (skip CIDR discovery) |
| `-Validate` | Validate OpenVAS CSV findings |
| (none) | Interactive mode -- launches TUI |

### Input

| Parameter | Description |
|-----------|-------------|
| `-CIDRs` | Comma-separated CIDR ranges (Scan mode) |
| `-CIDRFile` | Path to text file with one CIDR per line (Scan mode) |
| `-HostFile` | Path to text file with one IP/hostname per line (List mode) |
| `-InputCSV` | Path to OpenVAS CSV file (Validate mode) |

### Scanning Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Plugins` | All available | Comma-separated plugin names to run |
| `-MaxThreads` | 20 | Parallel thread count for scanning |
| `-TimeoutMs` | 5000 | Network timeout per test in milliseconds |
| `-Ports` | All (1-65535) | Port scanning scope: `top100`, comma-separated list, or omit for all |
| `-NoMenu` | Off | Skip interactive menus (requires sufficient CLI params) |
| `-Credential` | None | PSCredential for remote WMI/PSRemoting |

### Output

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Outputs` | From config | Comma-separated: MasterCSV, SummaryReport, SoftwareInventory, PerPluginCSV, DiscoveryCSV |
| `-OutputDir` | `.\output_reports` | Directory for all output files |

### Flag Rules (Software Version Check)

| Parameter | Description |
|-----------|-------------|
| `-FlagFilter` | Comma-separated wildcard patterns (e.g., `"*notepad*,*7-zip*"`) |
| `-FlagVersion` | Comma-separated version thresholds (e.g., `"LT8.9.1,LT24.9.0"`) |
| `-FlagLabel` | Comma-separated labels (e.g., `"CVE-2025-15556,CVE-2024-11477"`) |
| `-FlagFilterFile` | Path to a CSV rule file (replaces the three params above) |

---

## Configuration File

On first run, ScottyScan creates `scottyscan.json` in the same directory as the script. This file stores:

- Last-used mode, plugins, output selections, thread count, timeout
- Input file history (last 5 entries per input type)
- Port scanning configuration
- Saved flag rules for the Software Version Check

The config file is loaded on every run and updated when you make changes through the TUI. You can also edit it manually -- it is plain JSON. Delete it to reset all settings to defaults.

See [08-Configuration.md](08-Configuration.md) for the full config schema.

---

## Validating the Script (Parser Check)

Before running ScottyScan, especially after edits, you can validate that the PowerShell parser can read the script without syntax errors:

```powershell
powershell -NoProfile -Command '[System.Management.Automation.Language.Parser]::ParseFile("ScottyScan.ps1", [ref]$null, [ref]$errors); $errors.Count'
```

This command returns `0` if the script has no parse errors. Any non-zero result means there is a syntax error that must be fixed before the script will run.

The `dev-watch.ps1` helper script automates this -- it watches `ScottyScan.ps1` for changes and runs the parser check automatically on every save.

---

## Next Steps

- **[02-Modes-of-Operation.md](02-Modes-of-Operation.md)** -- Detailed explanation of Scan, List, and Validate modes
- **[03-Interactive-TUI.md](03-Interactive-TUI.md)** -- Full keyboard controls and menu navigation
- **[04-Plugin-System.md](04-Plugin-System.md)** -- How plugins work and how to write your own
- **[08-Configuration.md](08-Configuration.md)** -- Full CLI parameter and config file reference
