# Chapter 11: Development Guide

This guide is for developers working on ScottyScan, including AI coding assistants (Claude Code, Copilot, etc.). It documents real issues encountered during development, testing procedures, and project conventions.

---

## PowerShell Gotchas (Real Issues Hit During Development)

These are all real problems encountered during ScottyScan development. Every one of them caused bugs that were difficult to diagnose. Read this section before making any changes to the codebase.

### 1. $input is reserved

PowerShell has an automatic variable called `$input` that captures pipeline input. If you declare a variable named `$input`, it will silently be overridden by the pipeline mechanism. Your variable will appear empty with no error message.

**Always use alternative names:** `$userInput`, `$response`, `$inputValue`, etc.

```powershell
# WRONG - $input is a reserved automatic variable
$input = Read-Host "Enter value"
Write-Host $input    # Silently empty

# RIGHT
$userInput = Read-Host "Enter value"
Write-Host $userInput
```

### 2. Unicode breaks everything

Use ASCII only throughout the entire codebase. No em dashes (use `--` instead), no box-drawing characters (use `=`, `-`, `|` instead), no smart quotes (use straight quotes). PowerShell's console rendering and file encoding can mangle Unicode characters unpredictably, especially when:

- Writing to log files with different encoding settings
- Rendering in the TUI via `[Console]::Write`
- Moving between different terminal emulators
- Running on systems with different code pages

The ScottyScan banner uses only ASCII characters and has been manually corrected multiple times after edits introduced invisible Unicode.

### 3. Byte arrays in heredocs

When injecting byte arrays like `[byte[]](0x00, 0x9F)` into strings for RunspacePool execution, the PowerShell parser can mangle the byte values. This is critical for the TLS cipher suite codes used in `Send-TLSClientHello`.

ScottyScan handles this by defining helper functions as here-string blocks (`$script:HelperFunctionsString = @'...'@`) and injecting those strings into RunspacePool initial session state. Test byte array injection carefully, especially when modifying TLS ClientHello construction or SSH KEX_INIT parsing.

### 4. Comparison operators in strings

PowerShell's parser can interpret `-lt`, `-gt`, `-eq`, `-ne`, and other comparison operators even when they appear inside string literals, depending on context. The version comparison engine (`Test-VersionAgainstRule`) hit this issue when building rule expressions.

Use escaped or alternative representations when embedding comparison operator text in strings that will be parsed or evaluated. The current implementation uses text operators (LT, LE, GT, GE, EQ, NE) and symbol operators (<, <=, >, >=, =, !=) parsed via regex, avoiding the problem.

### 5. CSV with commas in fields

The OpenVAS CSV has commas inside the `nvt_name` column. For example:

```
Queued,192.168.100.164,host.example.com,3389,tcp,7.5,High,30,Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability (SSL/TLS, D(HE)ater)
```

The `nvt_name` field contains `(SSL/TLS, D(HE)ater)` with an embedded comma. `Import-Csv` will not handle this correctly because the OpenVAS export does not properly quote fields.

ScottyScan's `Import-OpenVASCSV` function handles this by splitting on commas, taking the first 8 fields positionally, and joining the remainder as `nvt_name`:

```powershell
$parts = $line -split ','
$nvtName = ($parts[8..($parts.Count - 1)] -join ',')
```

Do not use `Import-Csv` for files with irregular comma placement in unquoted fields.

### 6. IP normalization

OpenVAS exports zero-padded IPs like `192.168.101.001`. These will not match IPs returned by .NET's DNS resolution or TCP connections, which use unpadded integers like `192.168.101.1`.

Always normalize IPs by casting each octet through `[int]` to strip leading zeros:

```powershell
$normalizedIP = (($rawIP -split '\.') | ForEach-Object { [int]$_ }) -join '.'
# "192.168.101.001" -> "192.168.101.1"
```

### 7. Remote Registry service

The fastest software enumeration method (`Get-SoftwareFromRegistry`) connects to the Remote Registry service on target Windows hosts. This service must be running for the connection to succeed.

In many environments, the Remote Registry service is set to Manual or Disabled by default. It may need to be started remotely first via `sc.exe \\hostname start RemoteRegistry` or through WMI before attempting registry enumeration. If Remote Registry fails, ScottyScan falls back to PSRemoting, then WMI.

### 8. WMI Win32_Product is slow

`Get-CimInstance -ClassName Win32_Product` can trigger MSI reconfiguration (Windows Installer consistency checks) on the target host. This process can take several minutes per host and may generate event log entries.

ScottyScan uses `Get-SoftwareFromWMI` as the last-resort fallback only, after both Remote Registry and PSRemoting have failed. If you are adding new software enumeration logic, maintain this fallback ordering:

1. Remote Registry (fast, lightweight)
2. PSRemoting / Invoke-Command (medium, reads local registry)
3. WMI Win32_Product (slow, last resort)

### 9. Write-Host during TUI rendering

Never call `Write-Host` (or `Write-Log` without the `-Silent` switch) inside a `Write-LineAt` rendering loop. `Write-Host` outputs a newline character that corrupts the fixed-position display maintained by `[Console]::SetCursorPosition`.

The TUI rendering system (`Write-LineAt`, `Clear-Screen`, `Draw-Banner`) uses `[Console]::Write` specifically because it does NOT append a newline. Any stray `Write-Host` call during TUI rendering will cause the display to scroll and break the fixed-position layout.

For logging during TUI sections, use:

```powershell
Write-Log "message" -Silent    # Writes to log file only, no console output
```

### 10. ASCII art in heredocs

Backslashes, special characters, and whitespace alignment in the ScottyScan banner heredoc are fragile during editing. The banner has been manually corrected multiple times after edits introduced line-break issues, invisible characters, or spacing errors.

The banner is defined in `Draw-Banner` (around line 409) as a `$lines` array. Do not edit the banner unless absolutely necessary. If you must edit it, verify the result visually by running the script and checking console output.

### 11. [Console]::KeyAvailable key comparison

When checking for specific key presses (e.g., the `[E]` key to end discovery early), use the correct enum type:

```powershell
# WRONG - [ConsoleKeyCode] does not exist
if ($key.Key -eq [ConsoleKeyCode]::E) { ... }

# RIGHT - use [System.ConsoleKey]
if ($key.Key -eq [System.ConsoleKey]::E) { ... }
```

Using a non-existent type like `[ConsoleKeyCode]` will cause a runtime error that may not surface until the specific code path is reached.

---

## Testing

### Parser Validation

After every edit to `ScottyScan.ps1`, run the parser check to verify there are no syntax errors:

```powershell
powershell -NoProfile -Command '[System.Management.Automation.Language.Parser]::ParseFile("ScottyScan.ps1", [ref]$null, [ref]$errors); $errors.Count'
```

This should return `0`. If it returns any other number, there are parser errors that must be fixed before the script can run. This command parses the file without executing it, so it is safe to run at any time.

A helper script `_parsecheck.ps1` in the project root provides this same check.

### Testing Environment

ScottyScan is tested in the following environment:

- **Platform:** Windows domain environment with domain admin privileges
- **Test CIDRs:** 192.168.100.0/24 and 192.168.101.0/24
- **Target OS mix:** Windows Server 2012 R2 through current, Ubuntu 22/24, FreeBSD, Fedora 33
- **ESXi hosts:** .17 and .26 (D(HE)ater on SSH confirmed vulnerable -- 5 DHE kex algorithms detected)
- **Launch requirements:** Run from an elevated (admin) PowerShell console on a domain-joined workstation

### Current Test Status

| Feature | Status | Notes |
|---------|--------|-------|
| List mode end-to-end | TESTED | 14 hosts, all 4 plugins |
| Scan mode end-to-end | NOT TESTED | CIDR discovery -> scan pipeline |
| Validate mode end-to-end | NOT TESTED | OpenVAS CSV -> validation pipeline |
| Early exit ([E] during discovery) | NOT TESTED | With Y/N confirmation, partial result harvest |
| 7Zip-Version plugin | NOT WORKING | PSRemoting/WMI both fail -- needs credential passthrough or domain trust |
| TLS ClientHello handshake | TESTED | Confirmed against Windows RDP endpoints |
| SSH KEX_INIT parser | TESTED | Confirmed against Linux SSH endpoints |
| SSH-1 banner detection | TESTED | Confirmed working |
| CIDR expansion | TESTED | Working |
| RunspacePool parallelism | TESTED | Discovery + plugin scanning |
| Interactive TUI menu | TESTED | Arrow keys, spacebar, enter, escape, back-navigation |
| Software Version Check | NOT TESTED | Needs end-to-end testing (interactive + CLI) |

---

## File Watcher for Development

`dev-watch.ps1` provides a file system watcher for live-reload during development. It monitors the project directory for changes and can trigger actions (such as re-running the parser check) when files are modified.

---

## Adding New Plugins

1. Copy `plugins/_PluginTemplate.ps1` to a new file in the `plugins/` directory. Name it descriptively (e.g., `MyVuln-Check.ps1`). Files starting with underscore are skipped by the plugin loader.

2. Fill in the `Register-Validator` hashtable with:
   - `Name` -- unique identifier, shown in reports and menus
   - `NVTPattern` -- regex matched against OpenVAS `nvt_name` column (for Validate mode)
   - `TestBlock` -- scriptblock that receives `$Context` and returns `@{ Result; Detail }`
   - `ScanPorts` -- array of ports to test in Scan/List mode (empty array = software-class plugin)

3. See **[04-Plugin-System.md](04-Plugin-System.md)** for the full API documentation, available helper functions (`Test-TCPConnect`, `Send-TLSClientHello`, `Get-SSHKexAlgorithms`), and the `$Context` object properties.

4. Run the parser check (see above) to verify no syntax errors were introduced.

5. Test the new plugin in List mode with a small host file first, before running against full CIDR ranges.

### TestBlock return values

The `Result` field in the return hashtable must be one of these exact strings:

| Result | Meaning |
|--------|---------|
| `Vulnerable` | The vulnerability is confirmed present |
| `Remediated` | The vulnerability is confirmed NOT present (patched/mitigated) |
| `Unreachable` | The target port is not reachable |
| `Error` | An unexpected error occurred during the test |
| `Inconclusive` | The test could not determine the status |

---

## Code Organization

- **ScottyScan.ps1** is a single ~4800 line script. All functions are defined at the top of the file, with execution logic (the main entry point) at the bottom starting around line 4096.

- **Plugins** are separate `.ps1` files in the `plugins/` directory, loaded at runtime by `Load-Plugins`. Files starting with `_` are skipped.

- **Config persistence** is handled via `scottyscan.json`, which is auto-created on first run and stores all user selections between sessions.

- **Helper functions for RunspacePool** are defined twice: once as normal PowerShell functions (for direct use in the main thread) and once as here-strings (`$script:HelperFunctionsString`, `$script:SoftwareHelperString`, `$script:VersionHelperString`) that are injected into RunspacePool initial session state. This duplication is necessary because RunspacePool threads do not inherit the parent session's function definitions.

- **Output files** are written to `output_reports/` (configurable). Log files go to `output_reports/logs/`. Both directories are created automatically at startup.

---

## Conventions

- Use `Write-Log` for all informational output, not `Write-Host` directly (except inside TUI rendering code).
- Use `-Silent` switch on `Write-Log` during any TUI rendering loop.
- Use `Write-Section` for phase headers in the execution flow.
- All network connections use async TCP with configurable timeouts -- never use synchronous blocking calls.
- Results use a consistent hashtable format: `@{ IP; Port; Hostname; OS; PluginName; Result; Detail }`.
- Port 0 is used as a sentinel value for software-class plugins that run once per host without port scanning.
