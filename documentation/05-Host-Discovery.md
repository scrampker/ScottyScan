# 05 - Host Discovery

## Overview

Host discovery is the first phase in both Scan and List modes. It identifies live hosts on the network and enumerates their open TCP ports, hostnames, and operating systems.

- **Scan mode (-Scan)**: Expands CIDR ranges into individual IPs and performs a full discovery sweep across all of them.
- **List mode (-List)**: Reads IPs from a file (one per line) and performs port scanning on each listed host. Discovery still runs -- only the IP sourcing step is skipped.

The discovery subsystem is implemented primarily in the `Invoke-HostDiscovery` function (line ~2326 in ScottyScan.ps1), with OS fingerprinting handled by the separate `Invoke-OSFingerprint` function (line ~2683). Both use RunspacePool-based parallelism for concurrent host processing.

---

## CIDR Expansion

ScottyScan supports standard CIDR notation for specifying target networks. The `Expand-CIDR` function (line ~2303) handles the conversion from CIDR to individual IP addresses.

### Supported Formats

- Single subnet: `192.168.1.0/24` (254 hosts)
- Large range: `10.0.0.0/16` (65534 hosts)
- Small range: `192.168.1.0/28` (14 hosts)
- Multiple CIDRs: comma-separated in the TUI or CLI (e.g., `192.168.100.0/24,192.168.101.0/24`)

### How It Works

1. Parse the network address and prefix length from the CIDR string.
2. Compute the network and broadcast addresses using bitwise operations.
3. Generate all host addresses between network+1 and broadcast-1 (excluding the network and broadcast addresses themselves).
4. Return the list of IP strings.

Example: `192.168.100.0/24` expands to `192.168.100.1` through `192.168.100.254`.

---

## Port Scanning Approach

Every discovered IP undergoes TCP port scanning to identify open services. The scanning runs inside per-host RunspacePool jobs for parallelism.

### Batched Async TCP Connections

Port scanning uses a batched asynchronous connection pattern rather than sequential per-port probing:

1. Ports are divided into batches of **2000 connections**.
2. For each batch, a `TcpClient.BeginConnect()` call is issued for every port simultaneously.
3. The thread sleeps for the connect timeout (**500ms**).
4. All connections are checked: if `IsCompleted` is true and `EndConnect()` succeeds, the port is open.
5. All connections are closed regardless of result.
6. Progress is reported back to the main thread after each batch.

This approach allows scanning all 65535 ports on a single host in roughly 33 batches (about 17 seconds), compared to over 9 hours if each port were tested sequentially with a 500ms timeout.

### Priority Ordering

When scanning all 65535 ports, the port list is reordered so that high-value ports are tested first:

1. **Top 100 enterprise ports** (common services like 22, 80, 443, 3389, etc.) are placed first.
2. **Plugin-declared ScanPorts** are merged into the priority set (e.g., ports 443, 3389 for D(HE)ater-TLS, port 22 for D(HE)ater-SSH).
3. **Remaining ports** (1-65535 minus the priority set) are appended in ascending order.

This means results for common services appear in the real-time display within the first batch, even when a full port sweep is running.

### Progress Reporting

Each RunspacePool job receives a `[hashtable]::Synchronized()` reference called `$progressState`. After each batch completes, the job writes its current scan progress into this shared hashtable:

```
$progressState[$IP] = @{
    StartPort = <first port in batch>
    EndPort   = <last port in batch>
    Scanned   = <total ports scanned so far>
    Total     = <total ports to scan>
    OpenPorts = @(<ports found open so far>)
}
```

The main thread polls this hashtable during the display loop to show newly discovered open ports and scan progress percentages in real time.

---

## Port Scanning Options

Port scanning scope is configurable via the Settings menu (TUI step 6) or the CLI. The `Build-PortList` function (line ~170) resolves the selected option into an `int[]` port list.

### 1. All Ports (1-65535)

The default. Performs a full TCP sweep with priority ordering as described above. This is the most thorough option but takes the longest per host.

### 2. Top 100 Enterprise Ports

Scans only the most common enterprise service ports. Significantly faster than a full sweep. Suitable for quick reconnaissance where you only need to find standard services.

### 3. Plugin Recommended Ports

Scans only the ports declared in the `ScanPorts` arrays of the selected plugins. For example, if only D(HE)ater-TLS and SSH1-Deprecated are selected, this would scan ports 443, 3389, 8443 (TLS) and 22 (SSH). This is the fastest option when you know exactly which vulnerabilities you are testing for.

### 4. Custom Port List

User-specified comma-separated port numbers. Entered via the Settings menu or CLI. Plugin-declared ScanPorts are merged into the custom list to ensure selected plugins can still find their target services.

### 5. Management Ports Only (135, 445, 5985, 5986)

Automatically selected when **only** the Software Version Check is chosen (no vulnerability plugins). These are the minimum ports needed for the three remote enumeration methods:

| Port | Service | Used By |
|------|---------|---------|
| 135 | RPC/DCOM | WMI queries (Get-CimInstance) |
| 445 | SMB | Remote Registry access |
| 5985 | WinRM HTTP | PSRemoting (Invoke-Command) |
| 5986 | WinRM HTTPS | PSRemoting over TLS |

---

## OS Fingerprinting

OS fingerprinting runs as a separate phase (Phase 1b) after initial host discovery completes. The `Invoke-OSFingerprint` function enriches the live host list with detailed operating system information, updating each host's `.OS` property in place.

### Phase 1: TTL-Based Guessing (During Discovery)

During the initial discovery scan, a basic OS guess is made from the ICMP ping TTL value:

| TTL Range | OS Guess |
|-----------|----------|
| 1-64 | Linux/Unix |
| 65-128 | Windows |
| 129-255 | Network Device |

This provides a rough classification before the detailed fingerprinting phase runs.

### Phase 1b: Detailed OS Fingerprinting (Post-Discovery)

The `Invoke-OSFingerprint` function runs three techniques in sequence per host, stopping at the first technique that produces a definitive result.

#### Technique 1: CIM/WMI (Best for Windows)

- Probes management ports (135, 445, 5985) even if they were not in the original port scan.
- Queries `Win32_OperatingSystem` via `Get-CimInstance` for the OS caption and build number.
- Queries `Win32_ComputerSystem` for the domain name and computer name.
- Produces detailed results like `Windows Server 2019 Standard (Build 17763)`.
- Supports credential passthrough for cross-domain or non-domain environments.
- Detection method tag: `CIM/WMI`.

#### Technique 2: SSH Banner (Linux, BSD, ESXi)

If CIM/WMI did not succeed (i.e., the host is not Windows or management ports are unreachable), the fingerprinter connects to SSH ports (22, 1022, 2222) and reads the server identification banner.

The banner is matched against known patterns to identify the distribution:

| Banner Pattern | OS Identification |
|----------------|-------------------|
| `Ubuntu` | Ubuntu (with version mapped from OpenSSH version) |
| `Debian` | Debian |
| `Raspbian` | Raspbian |
| `FreeBSD` | FreeBSD |
| `NetBSD` | NetBSD |
| `OpenBSD` | OpenBSD |
| `Fedora` | Fedora |
| `CentOS` | CentOS |
| `AlmaLinux` | AlmaLinux |
| `Rocky` | Rocky Linux |
| `Red Hat` / `RHEL` | RHEL |
| `SUSE` | SUSE |
| `VMware` / `ESXi` | ESXi |
| `Cisco` | Cisco |
| `OpenSSH` (generic) | Windows (SSH) if RDP/management ports are open, otherwise Linux/Unix |

For Ubuntu, the OpenSSH version in the banner is mapped to a specific Ubuntu release using a lookup table (e.g., OpenSSH 9.6 maps to Ubuntu 24.04, OpenSSH 8.9 maps to Ubuntu 22.04).

Detection method tag: `SSH`.

#### Technique 3: Port Heuristic

If neither CIM/WMI nor SSH banner identification succeeded, the fingerprinter falls back to port-based heuristics. A host is classified as `Windows (probable)` if any of the following are true:

- Port 3389 (RDP) is open.
- Port 636 (LDAPS) is open.
- Port 135 (RPC/DCOM) is open.
- Port 5985 (WinRM) is open.
- Port 445 (SMB) is open but port 22 (SSH) is not.

Detection method tag: `Port-Heuristic`.

### Planned Enhancement

The legacy `Discover-And-Inventory.ps1` script contains additional fingerprinting capabilities that have not yet been merged:

- **SMB probe** for Windows version detection without requiring WMI/CIM access.
- **Multiple signal fusion** -- combining TTL, open ports, WMI, SSH banner, and SMB into a confidence-weighted OS determination with a numerical confidence score.

---

## Discovery CSV Output

After discovery and OS fingerprinting complete, ScottyScan can export a Discovery CSV that captures the full results. This CSV can be reused in subsequent runs to skip re-discovery.

### CSV Format

Header: `IP,Hostname,OS,TTL,OpenPorts`

```
IP,Hostname,OS,TTL,OpenPorts
192.168.100.5,dc01.domain.local,Windows Server 2019 Standard (Build 17763),128,53;88;135;389;443;445;636;3268;3269;3389;5985
192.168.100.10,ubuntu01.domain.local,Ubuntu 24.04,64,22;80;443
192.168.100.17,esxi01,ESXi,64,22;443;902
```

- **OpenPorts** are semicolon-separated (not comma-separated, to avoid conflicts with the CSV delimiter).
- **OS** contains the enriched OS string from fingerprinting, not the raw TTL guess.
- **TTL** is the raw ICMP TTL value from the ping reply.

### Discovery CSV Reuse

When starting a Scan or List mode run, ScottyScan checks the output directory for existing `Discovery_*.csv` files. If found, it offers the option to reuse them:

- **Scan mode**: The TUI presents a choice between entering new CIDRs or reusing a previous Discovery CSV. Selecting a CSV skips the entire discovery phase and loads hosts directly.
- **List mode**: If the input file has the Discovery CSV header (`IP,Hostname,OS,TTL,OpenPorts`), ScottyScan auto-detects it as a Discovery CSV and loads hosts without re-scanning.

This is useful for iterative testing: run discovery once against a large network, then reuse the Discovery CSV for multiple plugin scan passes without re-discovering hosts each time.

### Export and Import Functions

- `Export-DiscoveryCSV` (line ~3664): Writes the live host list to a CSV file.
- `Import-DiscoveryCSV` (line ~3621): Reads a Discovery CSV and returns an ArrayList of host hashtables in the same format as `Invoke-HostDiscovery` output (`@{ IP; Alive; Hostname; OS; TTL; OpenPorts }`).

---

## Real-Time Display During Discovery

Discovery progress is rendered as a fixed-position 15-row display block using `Write-LineAt` (a TUI primitive that writes at absolute console row positions without scrolling).

### Display Layout (15 rows)

```
Rows 1-6:   Host results window (last 6 entries)
Row 7:      Port discoveries header with running total
Rows 8-13:  Open port window (last 6 discoveries)
Row 14:     Spinner / status line
Row 15:     Hint line ("[E] to end scan early")
```

### Host Results Window (Rows 1-6)

Shows the most recent 6 host scan completions, scrolling upward as new results arrive:

```
  [1/254] [+] 192.168.100.5   ALIVE  11 open port(s)  Windows  dc01.domain.local
  [2/254] [-] 192.168.100.6   no response
  [3/254] [+] 192.168.100.10  ALIVE  3 open port(s)   Linux/Unix  ubuntu01.domain.local
```

- `[+]` in green: host is alive with open ports.
- `[-]` in dark gray: host did not respond to ping and has no open ports.

### Open Port Window (Rows 8-13)

Shows the most recent 6 port discoveries with a running total counter:

```
  -- Open ports (47 found) --
  [*] 192.168.100.5:445
  [*] 192.168.100.5:3389
  [*] 192.168.100.10:22
  [*] 192.168.100.10:80
```

Port discoveries appear in real time as the main thread polls the shared `$progressState` hashtable, so ports show up as soon as their batch completes -- even before the host's full scan is finished.

### Spinner / Status Line (Row 14)

A rotating spinner character with summary statistics:

```
  /  [12/254 hosts] 242 scanning  47 ports found -- ports 2001-4000 (6%)  elapsed 00:34
```

Fields: completed/total hosts, number still scanning, total ports found, current port range being scanned (from the first active host), elapsed time.

### Display Rendering

The display uses `[Console]::SetCursorPosition()` and `[Console]::Write()` via the `Write-LineAt` helper to overwrite the same 15 rows repeatedly. This avoids console scrolling and keeps the display compact. `[Console]::CursorVisible` is set to `$false` during rendering and restored in a `finally` block.

All logging during the display loop uses `Write-Log -Silent` to write to the log file without calling `Write-Host`, which would corrupt the fixed-position display.

---

## Early Exit

Users can press `[E]` during discovery to trigger an early exit. This is useful for large CIDR scans where enough hosts have been discovered.

### How It Works

1. The main polling loop checks `[Console]::KeyAvailable` on each iteration.
2. If the `E` key is detected (compared via `[System.ConsoleKey]::E`), a confirmation prompt replaces the hint line:
   ```
   End scan early? Press [Y] to confirm, any other key to continue
   ```
3. If `Y` is pressed, the early exit process begins.

### Partial Result Harvesting

When early exit is confirmed:

1. All pending RunspacePool jobs are examined.
2. For each pending host, the `$progressState` hashtable is checked for partial port data.
3. If partial data exists (some ports found before the scan was interrupted), a partial result is created and added to the live hosts list:
   ```
   [~] 192.168.100.50  PARTIAL 3 port(s) (12% scanned)
   ```
4. If no partial data exists, the host is marked as skipped:
   ```
   [~] 192.168.100.51  SKIPPED (scan ended early)
   ```
5. All pending PowerShell instances are stopped and disposed.
6. The final display is redrawn with all partial results.
7. An early exit event is logged with the count of processed hosts and discovered ports.

### After Early Exit

Partial results proceed normally to the OS fingerprinting phase and then to plugin scanning. Plugins will only be tested against the ports that were discovered before the scan was interrupted. Hosts with partial port data may miss some vulnerable services, but any ports found are valid and will be tested.
