# 04 - Plugin System

This chapter documents the ScottyScan plugin architecture: how plugins are loaded, the `Register-Validator` API contract, the helpers available inside test blocks, how the test matrix is scoped, a reference for every shipped plugin, and a step-by-step guide for writing new ones.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Plugin Lifecycle](#plugin-lifecycle)
- [Register-Validator API](#register-validator-api)
  - [Required Fields](#required-fields)
  - [Optional Fields](#optional-fields)
- [TestBlock Context Object](#testblock-context-object)
- [Required Return Format](#required-return-format)
- [Available Helper Functions](#available-helper-functions)
  - [Test-TCPConnect](#test-tcpconnect)
  - [Send-TLSClientHello](#send-tlsclienthello)
  - [Get-SSHKexAlgorithms](#get-sshkexalgorithms)
  - [Get-OSFromBanner](#get-osfrombanner)
- [Test Matrix Scoping](#test-matrix-scoping)
  - [Scan and List Modes](#scan-and-list-modes)
  - [Validate Mode](#validate-mode)
  - [Software-Class Plugins](#software-class-plugins)
- [RunspacePool Execution Model](#runspacepool-execution-model)
- [Existing Plugin Reference](#existing-plugin-reference)
  - [DHEater-TLS](#dheater-tls)
  - [DHEater-SSH](#dheater-ssh)
  - [SSH1-Deprecated](#ssh1-deprecated)
  - [7Zip-Version](#7zip-version)
- [Writing a New Plugin](#writing-a-new-plugin)
  - [Step-by-Step Guide](#step-by-step-guide)
  - [Full Example: HTTP Header Check](#full-example-http-header-check)
  - [Testing Your Plugin](#testing-your-plugin)
- [Common Pitfalls](#common-pitfalls)

---

## Architecture Overview

Plugins live in the `plugins/` directory alongside `ScottyScan.ps1`. Every `.ps1` file in that directory is auto-loaded at startup, with one exception: files whose names begin with an underscore (`_`) are skipped. This convention is used for the template file `_PluginTemplate.ps1`.

Each plugin file calls a single function -- `Register-Validator` -- with a hashtable that declares the plugin's identity, matching rules, target ports, and test logic. The test logic is provided as a `ScriptBlock` that runs in an isolated RunspacePool thread, not in the main PowerShell session. Helper functions are injected into each runspace as string definitions so they are available inside the test block.

The overall flow:

```
Startup
  |
  +-- Load-Plugins scans plugins/ for *.ps1 (excluding _* files)
  |     |
  |     +-- Each file is dot-sourced, calling Register-Validator
  |     +-- Validator hashtable is added to $script:Validators
  |
  +-- User selects plugins via TUI or CLI -Plugins parameter
  |
  +-- Invoke-PluginScan builds test matrix (targets x plugins x ports)
  |     |
  |     +-- Creates RunspacePool with configurable thread count
  |     +-- For each test: injects helper functions + TestBlock into a PowerShell instance
  |     +-- Polls for completion, prints results in real time
  |
  +-- Results collected into findings array for output generation
```

---

## Plugin Lifecycle

1. **Loading** -- `Load-Plugins` calls `Get-ChildItem` on the plugins directory, filters out files starting with `_`, and dot-sources each file. If a file throws an error during dot-sourcing, the error is logged and the remaining plugins continue loading.

2. **Registration** -- Each dot-sourced file calls `Register-Validator` with a hashtable. The function validates that the three required keys (`Name`, `NVTPattern`, `TestBlock`) are present, fills in defaults for optional keys, and appends the hashtable to the `$script:Validators` list.

3. **Selection** -- In the interactive TUI, plugins appear as checkboxes in the plugin selection menu. In CLI mode, the `-Plugins` parameter accepts a comma-separated list of plugin names. Only selected plugins participate in the scan.

4. **Matching (Validate mode only)** -- `Find-Validator` iterates through registered validators sorted by `Priority` (lower first) and returns the first one whose `NVTPattern` matches the OpenVAS `nvt_name`, optionally filtered by `PortFilter` and `ProtoFilter`.

5. **Execution** -- `Invoke-PluginScan` builds a test matrix, creates a RunspacePool, serializes each plugin's `TestBlock` into a string, wraps it with helper function definitions, and dispatches it to a thread. Results are polled and printed as they complete.

6. **Output** -- Each finding is a hashtable with IP, Port, Hostname, OS, PluginName, Result, and Detail. These are collected and passed to the output generators (Master CSV, summary report, per-plugin CSVs).

---

## Register-Validator API

A plugin registers itself by calling `Register-Validator` with a single hashtable argument. This is the full contract.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `Name` | string | Unique identifier for the plugin. Appears in console output, CSV columns, and report files. Must be distinct across all loaded plugins. |
| `NVTPattern` | string | Regular expression matched against the OpenVAS `nvt_name` column in Validate mode. Used by `Find-Validator` to route each CSV row to the correct plugin. Even if your plugin is only intended for Scan/List mode, this field is required -- use a pattern that describes what the plugin checks for. |
| `TestBlock` | ScriptBlock | The test logic. Receives a `$Context` hashtable as its only parameter. Must return a hashtable with `Result` and `Detail` keys. Runs in an isolated RunspacePool thread. |

If any required field is missing, `Register-Validator` logs an error and silently skips the plugin.

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Description` | string | `""` | Human-readable description of what this plugin checks for. |
| `Category` | string | `"General"` | Classification for grouping in reports. Common values: `Cryptography`, `Protocol`, `Software`. |
| `Priority` | int | `100` | Lower values are matched first when multiple plugins have overlapping `NVTPattern` regexes in Validate mode. All shipped plugins use priority 10 or 20. |
| `ScanPorts` | int[] | `@()` | Ports to test against in Scan and List modes. The plugin will only be executed against ports in this list that are actually open on the target host (intersection logic). An empty array designates a software-class plugin that runs once per host with port 0 as a sentinel. |
| `PortFilter` | string | `$null` | Regex matched against the port column in Validate mode for additional NVT matching precision. For example, `"^(443\|8443)$"` restricts matching to only those ports. |
| `ProtoFilter` | string | `$null` | Protocol filter for Validate mode NVT matching. `"tcp"` or `"udp"`. If `$null`, matches any protocol. |

### Example Registration

```powershell
Register-Validator @{
    Name        = "DHEater-TLS"
    Description = "D(HE)ater DoS on SSL/TLS (RDP, HTTPS, PostgreSQL)"
    Category    = "Cryptography"
    NVTPattern  = "Diffie-Hellman Ephemeral.*SSL/TLS|D\(HE\)ater.*SSL/TLS"
    Priority    = 10
    ScanPorts   = @(3389, 443, 5432, 636, 8443)
    TestBlock   = {
        param($Context)
        # ... test logic ...
    }
}
```

---

## TestBlock Context Object

The `TestBlock` scriptblock receives a single parameter, `$Context`, which is a hashtable with the following keys:

| Property | Type | Description |
|----------|------|-------------|
| `$Context.IP` | string | Target IP address (always normalized, never zero-padded). |
| `$Context.Port` | string | Target port number. For software-class plugins (empty `ScanPorts`), this is `"0"`. Cast to `[int]` when doing numeric operations. |
| `$Context.Hostname` | string | DNS hostname of the target. May be empty if hostname resolution failed. |
| `$Context.TimeoutMs` | int | Timeout in milliseconds for network operations. Configured via the Settings menu or `-TimeoutMs` CLI parameter. Default is 3000. |
| `$Context.Credential` | PSCredential | A `PSCredential` object for authenticated checks (PSRemoting, WMI, Remote Registry). Will be `$null` if no credentials were provided. Only relevant for software-class plugins that need remote access. |

**Important**: The `Port` value arrives as a string because it is interpolated into the runspace script. Always cast it with `[int]$Context.Port` when you need numeric comparison or when passing it to helper functions that expect an integer parameter.

---

## Required Return Format

Every `TestBlock` must return a hashtable with at least two keys:

```powershell
@{
    Result = "Vulnerable"   # One of the five valid result values
    Detail = "Human-readable explanation of what was found"
}
```

### Result Values

| Value | Meaning | Console Display | Color |
|-------|---------|-----------------|-------|
| `Vulnerable` | The vulnerability is confirmed present on the target. | `[VULN]` | Red |
| `Remediated` | The vulnerability has been fixed or the check passed. | `[FIXED]` | Green |
| `Unreachable` | Could not connect to the target port. The service is down, filtered, or the host is offline. | `[DOWN]` | DarkYellow |
| `Error` | An unexpected error occurred during the check. This typically means a bug in the plugin or an unanticipated network condition. | `[ERR]` | Gray |
| `Inconclusive` | The check ran but could not determine status definitively. For example, a software-class plugin that could not query the remote host via any method. | `[???]` | Gray |

### Optional Return Key: OS

Plugins can optionally include an `OS` key in their return hashtable:

```powershell
@{
    Result = "Vulnerable"
    Detail = "5 DHE kex algorithms found"
    OS     = "Ubuntu"
}
```

The scan engine uses OS data from the discovery phase (fingerprinting) as the primary source, but falls back to the plugin-reported `OS` value when the discovery OS is empty or generic (plain `"Linux/Unix"` or `"Windows"`). This is useful for SSH-based plugins where the banner reveals the specific Linux distribution.

---

## Available Helper Functions

These functions are defined in the main script and injected as string definitions into every RunspacePool thread. They are available for use inside any `TestBlock` without importing or declaring them.

### Test-TCPConnect

Tests whether a TCP port is reachable.

```
Test-TCPConnect -IP <string> -Port <int> -TimeoutMs <int>
```

**Returns:**
- `$true` -- Port is open and accepting connections
- `$false` -- Connection was actively refused (port closed or firewall RST)
- `$null` -- Connection timed out (no response within TimeoutMs)

**Example usage:**

```powershell
if (-not (Test-TCPConnect -IP $ip -Port $port -TimeoutMs $tout)) {
    return @{ Result = "Unreachable"; Detail = "Port $port not responding" }
}
```

**Implementation note:** Uses `System.Net.Sockets.TcpClient` with `BeginConnect` for async timeout control.

---

### Send-TLSClientHello

Sends a raw TLS 1.2 ClientHello with a specific cipher suite and checks whether the server accepts it. Used for testing whether a server supports specific (potentially vulnerable) cipher suites.

```
Send-TLSClientHello -IP <string> -Port <int> -CipherCode <byte[]> -TimeoutMs <int>
```

**Parameters:**
- `-CipherCode` -- A two-byte array representing the TLS cipher suite identifier. For example, `[byte[]](0x00, 0x9F)` is `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`.

**Returns:**
- `$true` -- Server responded with a ServerHello (cipher accepted)
- `$false` -- Server rejected the cipher (handshake alert or non-ServerHello response)
- `$null` -- Connection failed (timeout, refused, or TLS handshake error)

**Example usage:**

```powershell
$result = Send-TLSClientHello -IP $ip -Port $port `
    -CipherCode ([byte[]](0x00, 0x9F)) -TimeoutMs $tout

if ($null -eq $result) {
    return @{ Result = "Unreachable"; Detail = "TLS handshake failed" }
}
if ($result -eq $true) {
    return @{ Result = "Vulnerable"; Detail = "DHE cipher accepted" }
}
return @{ Result = "Remediated"; Detail = "DHE cipher rejected" }
```

**Implementation detail:** Constructs a valid TLS record layer packet with a ClientHello handshake message containing the specified cipher suite code. Includes a TLS 1.3 `supported_versions` extension advertising TLS 1.2. Reads the response and checks for a ServerHello (content type `0x16`, handshake type `0x02`).

---

### Get-SSHKexAlgorithms

Connects to an SSH service, reads the server banner, sends our own banner, then reads and parses the server's `SSH_MSG_KEXINIT` packet to extract the list of supported key exchange algorithms.

```
Get-SSHKexAlgorithms -IP <string> -Port <int> -TimeoutMs <int>
```

**Returns on success:**

```powershell
@{
    Banner        = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    KexAlgorithms = @("curve25519-sha256", "diffie-hellman-group14-sha256", ...)
}
```

**Returns on failure:** `$null` (connection timeout, refused, or protocol error).

**Example usage:**

```powershell
$kexInfo = Get-SSHKexAlgorithms -IP $ip -Port $port -TimeoutMs $tout
if ($null -eq $kexInfo) {
    return @{ Result = "Unreachable"; Detail = "SSH handshake failed" }
}

$dheAlgs = $kexInfo.KexAlgorithms | Where-Object { $_ -match '^diffie-hellman-' }
if ($dheAlgs.Count -gt 0) {
    return @{
        Result = "Vulnerable"
        Detail = "$($dheAlgs.Count) DHE kex: $($dheAlgs -join '; ')"
    }
}
```

**Implementation detail:** The function identifies itself as `SSH-2.0-ScottyScan_1.0` in the banner exchange. It parses the binary KEXINIT packet by reading the key exchange algorithm name-list from the correct offset (byte 22 after the packet header, following the 16-byte cookie). This is a single-connection operation -- banner read, banner send, KEXINIT read all happen on the same TCP socket.

---

### Get-OSFromBanner

Parses an SSH banner string and returns a human-readable OS name if a known distribution or platform signature is detected.

```
Get-OSFromBanner -Banner <string>
```

**Returns:** A string such as `"Ubuntu"`, `"Debian"`, `"FreeBSD"`, `"ESXi"`, `"Fedora"`, `"Cisco IOS"`, etc. Returns an empty string if no known pattern matches.

**Recognized patterns:** Ubuntu, Debian, Raspbian, NetBSD, FreeBSD, OpenBSD, Fedora, CentOS, AlmaLinux, Rocky Linux, RHEL/Red Hat, SUSE/SLED/SLES, Arch Linux, ESXi/VMware, Cisco IOS.

**Example usage:**

```powershell
$kexInfo = Get-SSHKexAlgorithms -IP $ip -Port $port -TimeoutMs $tout
$bannerOS = Get-OSFromBanner $kexInfo.Banner
return @{
    Result = "Remediated"
    Detail = "Check passed. Banner: $($kexInfo.Banner)"
    OS     = $bannerOS
}
```

---

## Test Matrix Scoping

This is one of the most important concepts in the plugin system. Plugins are NOT tested against every port discovered on a host. The test matrix is scoped differently depending on the operating mode.

### Scan and List Modes

In Scan and List modes, `Invoke-PluginScan` builds the test matrix by intersecting each plugin's `ScanPorts` with the host's actually discovered open ports:

```
For each target host:
    For each selected plugin:
        If plugin.ScanPorts is non-empty:
            ports_to_test = plugin.ScanPorts INTERSECT target.OpenPorts
            If ports_to_test is empty:
                Skip this plugin for this host entirely
            Else:
                Queue one test per port in ports_to_test
        Else (software-class plugin):
            Queue one test with port = 0
```

**Concrete example:** The DHEater-TLS plugin declares `ScanPorts = @(3389, 443, 5432, 636, 8443)`. If a target host has open ports 22, 80, 443, and 3389, the intersection is 443 and 3389. The plugin runs twice for that host -- once for port 443 and once for port 3389. Ports 5432, 636, and 8443 are skipped because they are not open.

If a host has no ports open from the plugin's `ScanPorts` list, the plugin is skipped entirely for that host and a debug log entry is written.

If there is no discovery data for a host (no `OpenPorts` array), the plugin falls back to testing all of its declared `ScanPorts`.

### Validate Mode

In Validate mode, the test matrix comes from the OpenVAS CSV file, not from discovery. Each row in the CSV specifies an exact IP, port, and NVT name. `Find-Validator` matches the NVT name to a plugin, and the plugin runs against that specific IP:port combination. There is no intersection with `ScanPorts` -- the port from the CSV row is used directly.

### Software-Class Plugins

Plugins with `ScanPorts = @()` are software-class plugins. They do not test network ports; instead, they query the host via PSRemoting, WMI, or other remote management mechanisms. These plugins run once per host with port `0` used as a sentinel value in the test queue.

The `7Zip-Version` plugin is the current example of this pattern.

---

## RunspacePool Execution Model

Understanding how plugins execute is important for writing correct test logic.

1. **Thread isolation** -- Each test runs in its own PowerShell runspace within a shared RunspacePool. Plugins cannot share state with each other or with the main thread. Global variables, module imports, and script-scope variables from the main session are not available.

2. **Helper injection** -- The helper functions (`Test-TCPConnect`, `Send-TLSClientHello`, `Get-SSHKexAlgorithms`, `Get-OSFromBanner`) are defined as a single here-string (`$script:HelperFunctionsString`) and prepended to every runspace script. This is why they are available inside `TestBlock` without explicit importing.

3. **TestBlock serialization** -- The `TestBlock` scriptblock is converted to a string via `.ToString()` and embedded in the runspace script. This means:
   - You cannot reference variables from the plugin file's scope (they are not captured)
   - You cannot use `$script:`, `$global:`, or module-level variables
   - Everything the TestBlock needs must come from `$Context` or from the injected helpers
   - Be careful with byte arrays and special characters -- they must survive string conversion

4. **Context injection** -- The `$Context` hashtable is constructed inside the runspace script using string interpolation from the test queue entry. IP, Port, Hostname, and TimeoutMs are injected as literal values.

5. **Error handling** -- If the TestBlock throws an unhandled exception, the wrapper catch block returns a result with `Result = "Error"` and the exception message as the `Detail`. This prevents a single plugin failure from crashing the entire scan.

6. **Real-time output** -- The main thread polls running jobs every 250ms. When a job completes, its result is immediately printed to the console and logged, then added to the findings collection. A spinner with elapsed time and completion count is displayed while tests are in progress.

---

## Existing Plugin Reference

### DHEater-TLS

**File:** `plugins/DHEater-TLS.ps1`

| Property | Value |
|----------|-------|
| Name | `DHEater-TLS` |
| Description | D(HE)ater DoS on SSL/TLS (RDP, HTTPS, PostgreSQL) |
| Category | Cryptography |
| CVEs | CVE-2002-20001, CVE-2022-40735, CVE-2024-41996 |
| NVTPattern | `Diffie-Hellman Ephemeral.*SSL/TLS\|D\(HE\)ater.*SSL/TLS` |
| Priority | 10 |
| ScanPorts | 3389, 443, 5432, 636, 8443 |

**How it works:** Sends TLS ClientHello messages with six different DHE cipher suites to the target port. Each cipher is tested individually using `Send-TLSClientHello`. If any DHE cipher is accepted by the server (ServerHello response), the target is `Vulnerable`. If all are rejected, it is `Remediated`. If the first connection attempt fails entirely, it is `Unreachable`.

**Tested ciphers:**
- `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` (0x00, 0x9F)
- `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` (0x00, 0x9E)
- `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256` (0x00, 0x6B)
- `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256` (0x00, 0x67)
- `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` (0x00, 0x39)
- `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` (0x00, 0x33)

**Detail output example:** `"4 DHE cipher(s) accepted: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384; TLS_DHE_RSA_WITH_AES_128_GCM_SHA256; TLS_DHE_RSA_WITH_AES_256_CBC_SHA256; TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"`

---

### DHEater-SSH

**File:** `plugins/DHEater-SSH.ps1`

| Property | Value |
|----------|-------|
| Name | `DHEater-SSH` |
| Description | D(HE)ater DoS on SSH key exchange |
| Category | Cryptography |
| CVEs | CVE-2002-20001, CVE-2022-40735, CVE-2024-41996 |
| NVTPattern | `Diffie-Hellman Ephemeral.*SSH\|D\(HE\)ater.*SSH` |
| Priority | 10 |
| ScanPorts | 22, 1022, 2222 |

**How it works:** Uses `Get-SSHKexAlgorithms` to perform a single SSH connection and parse the server's KEXINIT packet. Filters the returned key exchange algorithm list for entries starting with `diffie-hellman-`. If any are found, the target is `Vulnerable`. If only safe algorithms (ECDH, curve25519, sntrup) are present, it is `Remediated`.

Also calls `Get-OSFromBanner` on the SSH banner and includes the OS in the return hashtable for OS fingerprinting enrichment.

**Detail output example:** `"5 DHE kex: diffie-hellman-group-exchange-sha256; diffie-hellman-group16-sha512; diffie-hellman-group18-sha512; diffie-hellman-group14-sha256; diffie-hellman-group14-sha1"`

---

### SSH1-Deprecated

**File:** `plugins/SSH1-Deprecated.ps1`

| Property | Value |
|----------|-------|
| Name | `SSH1-Deprecated` |
| Description | Deprecated SSH-1 protocol detection |
| Category | Protocol |
| CVEs | CVE-2001-0361, CVE-2001-0572 |
| NVTPattern | `Deprecated SSH-1 Protocol` |
| Priority | 10 |
| ScanPorts | 22, 1022, 2222 |

**How it works:** Opens a raw TCP connection to the target port, reads the SSH server banner, and checks the protocol version prefix:
- `SSH-1.5` or `SSH-1.99` -- `Vulnerable` (SSH-1 supported, even if SSH-2 is also available via 1.99)
- `SSH-2.0` -- `Remediated` (SSH-2 only)
- Anything else -- `Inconclusive`

This plugin does NOT use `Get-SSHKexAlgorithms` because it only needs the banner, not the KEXINIT exchange. It manages its own TCP connection to minimize overhead.

Also calls `Get-OSFromBanner` for OS enrichment.

**Detail output example:** `"SSH-2 only. Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"`

---

### 7Zip-Version

**File:** `plugins/7Zip-Version.ps1`

| Property | Value |
|----------|-------|
| Name | `7Zip-Version` |
| Description | Outdated 7-Zip installations (remote check) |
| Category | Software |
| CVEs | CVE-2024-11477, CVE-2025-0411 |
| NVTPattern | `7-Zip.*Vulnerabilit\|7-Zip.*Mark-of-the-Web` |
| Priority | 20 |
| ScanPorts | `@()` (software-class plugin) |

**How it works:** This is a software-class plugin that runs once per host (port 0 sentinel). It queries the target for installed 7-Zip versions using two methods in a fallback chain:

1. **PSRemoting** (preferred) -- `Invoke-Command` to read the remote registry uninstall keys
2. **WMI** (fallback) -- `Get-WmiObject Win32_Product` query (slower, may trigger MSI reconfiguration)

If the installed 7-Zip version is below `24.9.0`, the target is `Vulnerable`. If at or above that version, it is `Remediated`. If both remote methods fail, it is `Inconclusive`.

Uses `$Context.Credential` for authenticated access. If credentials are not provided, the methods run under the current user's security context.

**Current status:** This plugin is untested in the current test environment due to credential passthrough issues with PSRemoting/WMI in the test domain.

**Detail output example:** `"Outdated via PSRemoting -- 7-Zip 23.01 (x64) v23.01 (needs >= 24.9.0)"`

---

## Writing a New Plugin

### Step-by-Step Guide

1. **Copy the template.** Copy `plugins/_PluginTemplate.ps1` to a new file with a descriptive name. The filename does not need to match the plugin `Name`, but it helps for organization.

    ```
    plugins/_PluginTemplate.ps1  -->  plugins/MyCheck-Name.ps1
    ```

2. **Set the required fields.** Edit the `Register-Validator` hashtable:
   - `Name` -- Pick a unique, descriptive name. This appears in all output.
   - `NVTPattern` -- Write a regex that matches the corresponding OpenVAS NVT name. If this plugin is only for Scan/List mode, write a descriptive pattern anyway (it is a required field).
   - `TestBlock` -- Write your test logic (see below).

3. **Set ScanPorts.** List the TCP ports your check applies to. If your check is not port-specific (software inventory, configuration audit), use an empty array `@()`.

4. **Implement the TestBlock.** Your scriptblock receives `$Context` and must return a hashtable with `Result` and `Detail`. Use the available helpers for network operations. Always handle the unreachable case.

5. **Drop the file in plugins/.** ScottyScan auto-loads it on the next run. No registration, manifest, or import statement required.

### Full Example: HTTP Header Check

This example plugin checks whether an HTTP server returns the `X-Frame-Options` header, which mitigates clickjacking attacks.

```powershell
# HttpClickjack-Check.ps1 - Missing X-Frame-Options header detection

Register-Validator @{
    Name        = "HttpClickjack-Check"
    Description = "Missing X-Frame-Options header on HTTP services"
    Category    = "Web Security"
    NVTPattern  = "Missing.*X-Frame-Options|Clickjacking"
    Priority    = 50
    ScanPorts   = @(80, 443, 8080, 8443)
    TestBlock   = {
        param($Context)
        $ip   = $Context.IP
        $port = [int]$Context.Port
        $tout = $Context.TimeoutMs

        # Step 1: Verify port is reachable
        $reachable = Test-TCPConnect -IP $ip -Port $port -TimeoutMs $tout
        if (-not $reachable) {
            return @{
                Result = "Unreachable"
                Detail = "Port $port not responding"
            }
        }

        # Step 2: Send a minimal HTTP request and read the response headers
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $ar = $client.BeginConnect($ip, $port, $null, $null)
            [void]$ar.AsyncWaitHandle.WaitOne($tout, $false)
            $client.EndConnect($ar)

            $stream = $client.GetStream()
            $stream.ReadTimeout  = $tout
            $stream.WriteTimeout = $tout

            $request = "HEAD / HTTP/1.1`r`nHost: $ip`r`nConnection: close`r`n`r`n"
            $reqBytes = [System.Text.Encoding]::ASCII.GetBytes($request)
            $stream.Write($reqBytes, 0, $reqBytes.Length)
            $stream.Flush()

            $buf = [byte[]]::new(4096)
            $n = $stream.Read($buf, 0, $buf.Length)
            $client.Close()

            $response = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
        } catch {
            try { $client.Close() } catch {}
            return @{
                Result = "Error"
                Detail = "HTTP request failed: $($_.Exception.Message)"
            }
        }

        # Step 3: Check for the X-Frame-Options header
        if ($response -match '(?i)X-Frame-Options:\s*(\S+)') {
            $value = $Matches[1]
            return @{
                Result = "Remediated"
                Detail = "X-Frame-Options present: $value"
            }
        } else {
            return @{
                Result = "Vulnerable"
                Detail = "X-Frame-Options header is missing from HTTP response on port $port"
            }
        }
    }
}
```

**Key points demonstrated in this example:**

- The plugin uses `Test-TCPConnect` first to check reachability before attempting the full HTTP exchange.
- Raw socket I/O is used rather than `Invoke-WebRequest` or `Invoke-RestMethod` because those cmdlets may not be available in the RunspacePool and they add overhead.
- Timeouts are applied to both the connection and the stream read/write operations.
- The TCP client is closed in both success and error paths (the catch block includes a `try { $client.Close() } catch {}` guard).
- The response is parsed with a simple regex rather than a full HTTP parser, which is sufficient for header detection.
- All five result values are covered: `Unreachable` (port down), `Error` (request failed), `Vulnerable` (header missing), and `Remediated` (header present). `Inconclusive` would be appropriate if the response were malformed or ambiguous.

### Testing Your Plugin

1. **Parser check.** Before running, verify the plugin file parses without errors:

    ```powershell
    powershell -NoProfile -Command '
        [System.Management.Automation.Language.Parser]::ParseFile(
            "plugins\MyCheck-Name.ps1", [ref]$null, [ref]$errors
        )
        $errors.Count
    '
    ```

    A return of `0` means no parse errors.

2. **List mode with a single host.** The fastest way to test a new plugin:

    ```powershell
    .\ScottyScan.ps1 -List -HostFile .\test_target.txt -Plugins "MyCheck-Name" -NoMenu
    ```

    Where `test_target.txt` contains a single IP you know has the relevant service running.

3. **Check the log.** After a run, open the log file in `output_reports/logs/` to see the full (untruncated) detail strings and any debug messages about port intersection.

4. **Validate mode test.** If your plugin is intended for OpenVAS validation, create a single-row CSV with the correct NVT name and run:

    ```powershell
    .\ScottyScan.ps1 -Validate -InputCSV .\test_finding.csv -NoMenu
    ```

---

## Common Pitfalls

These are real issues encountered during plugin development for ScottyScan. Review them before writing your first plugin.

### Do not reference external variables

The `TestBlock` is serialized to a string and injected into an isolated runspace. Any variable references outside of `$Context` and the injected helpers will be `$null` at runtime. If you need a constant value, define it inside the TestBlock.

```powershell
# WRONG -- $safeVersion is not available in the runspace
$safeVersion = [version]"24.9.0"
TestBlock = {
    param($Context)
    if ($installed -lt $safeVersion) { ... }  # $safeVersion is $null
}

# RIGHT -- define it inside the TestBlock
TestBlock = {
    param($Context)
    $safeVersion = [version]"24.9.0"
    if ($installed -lt $safeVersion) { ... }
}
```

### Byte arrays in scriptblocks need care

When the TestBlock is serialized to a string via `.ToString()`, byte array literals like `[byte[]](0x00, 0x9F)` must survive the conversion. In practice this works for simple inline byte arrays, but complex constructions or byte arrays stored in variables outside the TestBlock will not transfer. Always define byte arrays inline within the TestBlock.

### Always close TCP clients

If your plugin opens a `TcpClient`, you must close it in all code paths -- success, failure, and exception. Leaked TCP connections will exhaust available sockets when scanning many hosts. Use a try/catch/finally pattern:

```powershell
try {
    $client = New-Object System.Net.Sockets.TcpClient
    # ... use the client ...
    $client.Close()
} catch {
    try { $client.Close() } catch {}
    return @{ Result = "Error"; Detail = "..." }
}
```

### Do not use Write-Host or Write-Output

Your TestBlock runs in an isolated runspace. `Write-Host` output will not appear anywhere. `Write-Output` or bare expressions will be captured as the runspace return value and may interfere with result parsing. Only use `return @{ Result = ...; Detail = ... }` for output.

### Cast $Context.Port to int

The port value arrives as a string because it is interpolated into the runspace script. If you pass it to a function expecting `[int]` or compare it numerically, cast it first:

```powershell
$port = [int]$Context.Port
```

### The $input variable is reserved

PowerShell reserves `$input` as an automatic variable for pipeline input. Never use `$input` as a variable name in your TestBlock. Use `$userInput`, `$response`, or another name instead.

### Minimize connection count

For performance across large scans, minimize the number of TCP connections your plugin makes per test. The DHEater-TLS plugin makes up to 6 connections (one per cipher), which is acceptable because each connection is lightweight and short-lived. But if you can get all the data you need from a single connection, prefer that approach. The DHEater-SSH and SSH1-Deprecated plugins both complete their checks in a single TCP connection.

### ScanPorts determines when your plugin runs

If your plugin declares `ScanPorts = @(22)` but the target only has port 443 open, your plugin will be skipped entirely for that host. This is by design -- it prevents futile connection attempts. Make sure your `ScanPorts` list is comprehensive for all ports where the vulnerability or condition you are checking could exist.

### Priority matters for overlapping NVT patterns

If two plugins have NVT patterns that could both match the same OpenVAS finding, the one with the lower `Priority` value wins. The shipped plugins use priority 10 for core vulnerability checks and 20 for software checks. Use priority 50+ for custom plugins to avoid accidentally overriding built-in matching.
