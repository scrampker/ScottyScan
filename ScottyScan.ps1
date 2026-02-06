<#
.SYNOPSIS
    ScottyScan - Environment vulnerability scanner and validator.

.DESCRIPTION
    Unified tool for network discovery, vulnerability scanning, and OpenVAS
    finding validation. Menu-driven for interactive use, fully parameterized
    for scripting.

    Modes:
      -Scan      Network discovery (CIDR sweep) + vulnerability scanning
      -List      Scan specific hosts from a file (skip discovery)
      -Validate  Validate OpenVAS CSV findings against live hosts

    Build: 2026-02-06T12:00:00 | Version: 1.0.0

.PARAMETER Scan
    Network scan mode. Discovers hosts on CIDRs, fingerprints OS, runs plugins.

.PARAMETER List
    List scan mode. Reads IPs/hostnames from a file, runs plugins against them.

.PARAMETER Validate
    Validate mode. Reads an OpenVAS CSV and validates each finding.

.PARAMETER CIDRs
    Comma-separated CIDR ranges for -Scan mode.

.PARAMETER CIDRFile
    Path to a text file with one CIDR per line.

.PARAMETER HostFile
    Path to a text file with one IP/hostname per line (for -List mode).

.PARAMETER InputCSV
    Path to the OpenVAS CSV (for -Validate mode).

.PARAMETER Plugins
    Comma-separated list of plugin names to run. Default: all available.

.PARAMETER Outputs
    Comma-separated list of output types: MasterCSV, SummaryReport,
    SoftwareInventory, PerPluginCSV, DiscoveryCSV. Default from config.

.PARAMETER MaxThreads
    Parallel thread count. Default: 20 (or from config).

.PARAMETER TimeoutMs
    Network timeout per test in ms. Default: 5000 (or from config).

.PARAMETER OutputDir
    Directory for all outputs. Default: .\output_reports

.PARAMETER NoMenu
    Skip all interactive menus. Requires sufficient CLI parameters.

.PARAMETER Credential
    PSCredential for remote WMI/PSRemoting checks.

.PARAMETER Ports
    TCP ports to probe during discovery. Default: 22,80,135,443,445,3389

.EXAMPLE
    # Interactive - launches menu
    .\ScottyScan.ps1

.EXAMPLE
    # CLI network scan
    .\ScottyScan.ps1 -Scan -CIDRs "192.168.100.0/24,192.168.101.0/24" -NoMenu

.EXAMPLE
    # CLI list scan
    .\ScottyScan.ps1 -List -HostFile .\targets.txt -Plugins "DHEater-TLS,DHEater-SSH" -NoMenu

.EXAMPLE
    # CLI validate
    .\ScottyScan.ps1 -Validate -InputCSV .\vulns.csv -NoMenu
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Scan,

    [Parameter(ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(ParameterSetName = 'Validate')]
    [switch]$Validate,

    [string]$CIDRs,
    [string]$CIDRFile,
    [string]$HostFile,
    [string]$InputCSV,
    [string]$Plugins,
    [string]$Outputs,
    [int]$MaxThreads = 0,
    [int]$TimeoutMs = 0,
    [string]$OutputDir = "",
    [switch]$NoMenu,
    [PSCredential]$Credential,
    [string]$Ports,
    [string]$SoftwareFilter,
    [string]$PluginDir
)

# ============================================================
#  GLOBALS
# ============================================================
$script:Version      = "1.0.0"
$script:Build        = "2026-02-06"
$script:ConfigFile   = Join-Path $PSScriptRoot "scottyscan.json"
$script:Config       = $null
$script:Validators   = [System.Collections.ArrayList]::new()
$script:LogFile      = $null
$script:Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"

$ErrorActionPreference = 'Continue'

# ============================================================
#  DISPLAY HELPERS
# ============================================================

function Write-Banner {
    $banner = @"

  ============================================
   ___           _   _         ___
  / __| __ ___  | |_| |_ _  _/ __| __ __ _ _ _
  \__ \/ _/ _ \ |  _|  _| || \__ \/ _/ _' | ' \
  |___/\__\___/  \__|\__|\_, |___/\__\__,_|_||_|
                         |__/
  Environment Scanner & Validator  v$($script:Version)
  Build: $($script:Build)
  ============================================
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  --- $Title ---" -ForegroundColor White
    Write-Host ""
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "OK"    { "Green" }
        "DEBUG" { "DarkGray" }
        default { "Gray" }
    }
    Write-Host "  $line" -ForegroundColor $color
    if ($script:LogFile) {
        $line | Out-File -Append -FilePath $script:LogFile -Encoding UTF8
    }
}

function Write-Status {
    param([string]$Label, [string]$Value, [string]$Color = "White")
    Write-Host ("  {0,-28} " -f $Label) -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

# ============================================================
#  INTERACTIVE MENU SYSTEM
# ============================================================

function Show-CheckboxMenu {
    <#
    .SYNOPSIS
        Displays an interactive checkbox menu. Returns array of selected items.
    .PARAMETER Title
        Menu title displayed above options.
    .PARAMETER Items
        Array of hashtables: @{ Name = "display"; Value = "returnValue"; Selected = $true/$false; Description = "optional" }
    .PARAMETER AllowSelectAll
        Show Select All / None toggle.
    #>
    param(
        [string]$Title,
        [array]$Items,
        [switch]$AllowSelectAll,
        [switch]$SingleSelect
    )

    # Clone selection state
    $selections = @()
    foreach ($item in $Items) {
        $selections += @{
            Name        = $item.Name
            Value       = $item.Value
            Selected    = [bool]$item.Selected
            Description = $item.Description
        }
    }

    $cursorPos = 0

    while ($true) {
        # Render
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Yellow
        if ($SingleSelect) {
            Write-Host "  (Use number keys to select, Enter to confirm)" -ForegroundColor DarkGray
        } else {
            Write-Host "  (Toggle: number key | A=All | N=None | Enter=Confirm)" -ForegroundColor DarkGray
        }
        Write-Host ""

        for ($i = 0; $i -lt $selections.Count; $i++) {
            $sel = $selections[$i]
            $marker = if ($sel.Selected) { "[X]" } else { "[ ]" }
            $num = $i + 1
            $nameStr = $sel.Name
            $descStr = if ($sel.Description) { " - $($sel.Description)" } else { "" }

            Write-Host "    " -NoNewline
            if ($sel.Selected) {
                Write-Host ("{0} {1}" -f $marker, "$num.") -NoNewline -ForegroundColor Green
            } else {
                Write-Host ("{0} {1}" -f $marker, "$num.") -NoNewline -ForegroundColor DarkGray
            }
            Write-Host (" {0}" -f $nameStr) -NoNewline -ForegroundColor White
            Write-Host $descStr -ForegroundColor DarkGray
        }

        Write-Host ""
        $prompt = if ($SingleSelect) { "  Choice" } else { "  Toggle (#), A=All, N=None, Enter=Done" }
        $input = Read-Host $prompt

        if ([string]::IsNullOrWhiteSpace($input)) {
            # Confirm
            break
        }

        $inputUpper = $input.Trim().ToUpper()

        if ($inputUpper -eq 'A' -and $AllowSelectAll -and -not $SingleSelect) {
            foreach ($s in $selections) { $s.Selected = $true }
            continue
        }

        if ($inputUpper -eq 'N' -and $AllowSelectAll -and -not $SingleSelect) {
            foreach ($s in $selections) { $s.Selected = $false }
            continue
        }

        # Try numeric toggle
        $nums = $inputUpper -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
        foreach ($n in $nums) {
            $idx = [int]$n - 1
            if ($idx -ge 0 -and $idx -lt $selections.Count) {
                if ($SingleSelect) {
                    # Deselect all, select this one
                    foreach ($s in $selections) { $s.Selected = $false }
                    $selections[$idx].Selected = $true
                } else {
                    $selections[$idx].Selected = -not $selections[$idx].Selected
                }
            }
        }
    }

    return ($selections | Where-Object { $_.Selected } | ForEach-Object { $_.Value })
}

function Show-FilePrompt {
    <#
    .SYNOPSIS
        Prompts for a file path with optional GUI file picker and last-used memory.
    #>
    param(
        [string]$Prompt,
        [string]$LastPath,
        [string]$Filter = "All files (*.*)|*.*",
        [switch]$MustExist
    )

    $displayLast = ""
    if ($LastPath) {
        $displayLast = " [last: $LastPath]"
    }

    while ($true) {
        Write-Host ""
        Write-Host "  $Prompt$displayLast" -ForegroundColor Yellow
        Write-Host "  (Type path, 'browse' for file picker, or Enter for last used)" -ForegroundColor DarkGray
        $response = Read-Host "  Path"

        if ([string]::IsNullOrWhiteSpace($response) -and $LastPath) {
            if (-not $MustExist -or (Test-Path $LastPath)) {
                return $LastPath
            }
            Write-Host "  Last path no longer exists: $LastPath" -ForegroundColor Red
            continue
        }

        if ($response.Trim().ToLower() -eq 'browse') {
            $picked = Show-FilePicker -Filter $Filter -LastFolder (Split-Path $LastPath -Parent -ErrorAction SilentlyContinue)
            if ($picked) { return $picked }
            Write-Host "  No file selected." -ForegroundColor Yellow
            continue
        }

        $resolved = $response.Trim().Trim('"').Trim("'")
        if ($MustExist -and -not (Test-Path $resolved)) {
            Write-Host "  File not found: $resolved" -ForegroundColor Red
            continue
        }

        return $resolved
    }
}

function Show-FilePicker {
    param([string]$Filter, [string]$LastFolder)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Filter = $Filter
        if ($LastFolder -and (Test-Path $LastFolder)) {
            $dialog.InitialDirectory = $LastFolder
        }
        $dialog.Title = "ScottyScan - Select File"
        $result = $dialog.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.FileName
        }
    } catch {
        Write-Host "  (GUI file picker unavailable in this session)" -ForegroundColor DarkGray
    }
    return $null
}

function Show-TextPrompt {
    param(
        [string]$Prompt,
        [string]$Default,
        [string]$LastValue
    )
    $displayDefault = ""
    if ($LastValue) {
        $displayDefault = " [last: $LastValue]"
    } elseif ($Default) {
        $displayDefault = " [default: $Default]"
    }
    Write-Host ""
    Write-Host "  $Prompt$displayDefault" -ForegroundColor Yellow
    $response = Read-Host "  Value"
    if ([string]::IsNullOrWhiteSpace($response)) {
        if ($LastValue) { return $LastValue }
        return $Default
    }
    return $response.Trim()
}

# ============================================================
#  CONFIGURATION / STATE
# ============================================================

function Load-Config {
    if (Test-Path $script:ConfigFile) {
        try {
            $script:Config = Get-Content $script:ConfigFile -Raw | ConvertFrom-Json
            return
        } catch {
            Write-Log "Failed to load config: $_" "WARN"
        }
    }
    # Defaults
    $script:Config = [PSCustomObject]@{
        LastMode         = ""
        LastCIDRs        = ""
        LastCIDRFile     = ""
        LastHostFile     = ""
        LastInputCSV     = ""
        LastBrowseFolder = ""
        DefaultThreads   = 20
        DefaultTimeoutMs = 5000
        DefaultPlugins   = @()
        DefaultOutputs   = @("MasterCSV", "SummaryReport")
        DefaultPorts     = "22,80,135,443,445,3389"
        LastOutputDir    = ".\output_reports"
    }
}

function Save-Config {
    try {
        $script:Config | ConvertTo-Json -Depth 5 | Out-File $script:ConfigFile -Encoding UTF8
    } catch {
        Write-Log "Failed to save config: $_" "WARN"
    }
}

function Update-ConfigValue {
    param([string]$Key, $Value)
    if ($script:Config.PSObject.Properties.Name -contains $Key) {
        $script:Config.$Key = $Value
    } else {
        $script:Config | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force
    }
}

# ============================================================
#  PLUGIN LOADER
# ============================================================

function Register-Validator {
    param([hashtable]$Validator)
    foreach ($key in @('Name', 'NVTPattern', 'TestBlock')) {
        if (-not $Validator.ContainsKey($key)) {
            Write-Log "Plugin registration failed: missing '$key'" "ERROR"
            return
        }
    }
    if (-not $Validator.ContainsKey('Priority'))     { $Validator['Priority'] = 100 }
    if (-not $Validator.ContainsKey('PortFilter'))    { $Validator['PortFilter'] = $null }
    if (-not $Validator.ContainsKey('ProtoFilter'))   { $Validator['ProtoFilter'] = $null }
    if (-not $Validator.ContainsKey('Description'))   { $Validator['Description'] = "" }
    if (-not $Validator.ContainsKey('ScanPorts'))     { $Validator['ScanPorts'] = @() }
    if (-not $Validator.ContainsKey('Category'))      { $Validator['Category'] = "General" }
    [void]$script:Validators.Add($Validator)
}

function Load-Plugins {
    param([string]$Dir)
    if (-not $Dir) {
        $Dir = Join-Path $PSScriptRoot "plugins"
    }
    if (-not (Test-Path $Dir)) {
        Write-Log "Plugin directory not found: $Dir" "WARN"
        return
    }
    $files = Get-ChildItem -Path $Dir -Filter "*.ps1" -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -notmatch '^_' }  # Skip _templates
    foreach ($f in $files) {
        try {
            . $f.FullName
            Write-Log "Loaded plugin: $($f.BaseName)" "DEBUG"
        } catch {
            Write-Log "Failed to load plugin $($f.Name): $_" "ERROR"
        }
    }
    Write-Log ("{0} plugins loaded, {1} validators registered" -f $files.Count, $script:Validators.Count)
}

function Find-Validator {
    param([string]$NVTName, [string]$Port, [string]$Protocol)
    $sorted = $script:Validators | Sort-Object { $_.Priority }
    foreach ($v in $sorted) {
        if ($NVTName -notmatch $v.NVTPattern) { continue }
        if ($v.PortFilter -and $Port -notmatch $v.PortFilter) { continue }
        if ($v.ProtoFilter -and $Protocol -and $Protocol -ne $v.ProtoFilter) { continue }
        return $v
    }
    return $null
}

# ============================================================
#  NETWORK HELPERS (shared with plugins via helper injection)
# ============================================================

function Test-TCPConnect {
    param([string]$IP, [int]$Port, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $waited) { $client.Close(); return $false }
        $client.EndConnect($ar)
        $client.Close()
        return $true
    } catch { try { $client.Close() } catch {}; return $false }
}

function Send-TLSClientHello {
    param([string]$IP, [int]$Port, [byte[]]$CipherCode, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $waited) { $client.Close(); return $null }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs
        $random = [byte[]]::new(32)
        (New-Object Random).NextBytes($random)
        $cipherLen = [byte[]](0x00, 0x02)
        $extensions = @([byte[]](0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x03))
        $extBytes = [byte[]]($extensions | ForEach-Object { $_ })
        $extLenBytes = [System.BitConverter]::GetBytes([uint16]$extBytes.Length)
        [Array]::Reverse($extLenBytes)
        $hello = @(
            [byte[]](0x03, 0x03), $random, [byte[]](0x00),
            $cipherLen, $CipherCode, [byte[]](0x01, 0x00),
            $extLenBytes, $extBytes
        )
        $helloBytes = [byte[]]($hello | ForEach-Object { $_ })
        $helloLen = [System.BitConverter]::GetBytes([uint32]$helloBytes.Length)
        [Array]::Reverse($helloLen)
        $handshake = @([byte[]](0x01), $helloLen[1..3], $helloBytes)
        $hsBytes = [byte[]]($handshake | ForEach-Object { $_ })
        $hsLen = [System.BitConverter]::GetBytes([uint16]$hsBytes.Length)
        [Array]::Reverse($hsLen)
        $record = @([byte[]](0x16), [byte[]](0x03, 0x01), $hsLen, $hsBytes)
        $recordBytes = [byte[]]($record | ForEach-Object { $_ })
        $stream.Write($recordBytes, 0, $recordBytes.Length)
        $stream.Flush()
        $buf = [byte[]]::new(4096)
        $bytesRead = $stream.Read($buf, 0, $buf.Length)
        $client.Close()
        if ($bytesRead -ge 6 -and $buf[0] -eq 0x16 -and $buf[5] -eq 0x02) { return $true }
        return $false
    } catch { try { $client.Close() } catch {}; return $null }
}

function Get-SSHKexAlgorithms {
    param([string]$IP, [int]$Port, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $waited) { $client.Close(); return $null }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $buf = [byte[]]::new(4096)
        $bytesRead = $stream.Read($buf, 0, $buf.Length)
        $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $bytesRead).Trim()
        $ourBanner = "SSH-2.0-ScottyScan_$($script:Version)`r`n"
        $bannerBytes = [System.Text.Encoding]::ASCII.GetBytes($ourBanner)
        $stream.Write($bannerBytes, 0, $bannerBytes.Length)
        $stream.Flush()
        Start-Sleep -Milliseconds 200
        $kexBuf = [byte[]]::new(16384)
        $kexRead = $stream.Read($kexBuf, 0, $kexBuf.Length)
        $client.Close()
        if ($kexRead -lt 20) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $msgType = $kexBuf[5]
        if ($msgType -ne 20) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $offset = 22
        if ($offset + 4 -gt $kexRead) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $kexListLen = [System.BitConverter]::ToUInt32(
            @($kexBuf[$offset+3], $kexBuf[$offset+2], $kexBuf[$offset+1], $kexBuf[$offset]), 0)
        $offset += 4
        if ($offset + $kexListLen -gt $kexRead) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $kexList = [System.Text.Encoding]::ASCII.GetString($kexBuf, $offset, $kexListLen)
        return @{ Banner = $banner; KexAlgorithms = ($kexList -split ',') }
    } catch { try { $client.Close() } catch {}; return $null }
}

# Stringified versions for runspace injection
$script:HelperFunctionsString = @'
function Test-TCPConnect {
    param([string]$IP, [int]$Port, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $waited) { $client.Close(); return $false }
        $client.EndConnect($ar)
        $client.Close()
        return $true
    } catch { try { $client.Close() } catch {}; return $false }
}

function Send-TLSClientHello {
    param([string]$IP, [int]$Port, [byte[]]$CipherCode, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $waited) { $client.Close(); return $null }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs
        $random = [byte[]]::new(32)
        (New-Object Random).NextBytes($random)
        $cipherLen = [byte[]](0x00, 0x02)
        $extensions = @([byte[]](0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x03))
        $extBytes = [byte[]]($extensions | ForEach-Object { $_ })
        $extLenBytes = [System.BitConverter]::GetBytes([uint16]$extBytes.Length)
        [Array]::Reverse($extLenBytes)
        $hello = @(
            [byte[]](0x03, 0x03), $random, [byte[]](0x00),
            $cipherLen, $CipherCode, [byte[]](0x01, 0x00),
            $extLenBytes, $extBytes
        )
        $helloBytes = [byte[]]($hello | ForEach-Object { $_ })
        $helloLen = [System.BitConverter]::GetBytes([uint32]$helloBytes.Length)
        [Array]::Reverse($helloLen)
        $handshake = @([byte[]](0x01), $helloLen[1..3], $helloBytes)
        $hsBytes = [byte[]]($handshake | ForEach-Object { $_ })
        $hsLen = [System.BitConverter]::GetBytes([uint16]$hsBytes.Length)
        [Array]::Reverse($hsLen)
        $record = @([byte[]](0x16), [byte[]](0x03, 0x01), $hsLen, $hsBytes)
        $recordBytes = [byte[]]($record | ForEach-Object { $_ })
        $stream.Write($recordBytes, 0, $recordBytes.Length)
        $stream.Flush()
        $buf = [byte[]]::new(4096)
        $bytesRead = $stream.Read($buf, 0, $buf.Length)
        $client.Close()
        if ($bytesRead -ge 6 -and $buf[0] -eq 0x16 -and $buf[5] -eq 0x02) { return $true }
        return $false
    } catch { try { $client.Close() } catch {}; return $null }
}

function Get-SSHKexAlgorithms {
    param([string]$IP, [int]$Port, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $waited) { $client.Close(); return $null }
        $client.EndConnect($ar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $buf = [byte[]]::new(4096)
        $bytesRead = $stream.Read($buf, 0, $buf.Length)
        $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $bytesRead).Trim()
        $ourBanner = "SSH-2.0-ScottyScan_1.0`r`n"
        $bannerBytes = [System.Text.Encoding]::ASCII.GetBytes($ourBanner)
        $stream.Write($bannerBytes, 0, $bannerBytes.Length)
        $stream.Flush()
        Start-Sleep -Milliseconds 200
        $kexBuf = [byte[]]::new(16384)
        $kexRead = $stream.Read($kexBuf, 0, $kexBuf.Length)
        $client.Close()
        if ($kexRead -lt 20) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $msgType = $kexBuf[5]
        if ($msgType -ne 20) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $offset = 22
        if ($offset + 4 -gt $kexRead) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $kexListLen = [System.BitConverter]::ToUInt32(
            @($kexBuf[$offset+3], $kexBuf[$offset+2], $kexBuf[$offset+1], $kexBuf[$offset]), 0)
        $offset += 4
        if ($offset + $kexListLen -gt $kexRead) { return @{ Banner = $banner; KexAlgorithms = @() } }
        $kexList = [System.Text.Encoding]::ASCII.GetString($kexBuf, $offset, $kexListLen)
        return @{ Banner = $banner; KexAlgorithms = ($kexList -split ',') }
    } catch { try { $client.Close() } catch {}; return $null }
}
'@

# ============================================================
#  CIDR / DISCOVERY ENGINE
# ============================================================

function Expand-CIDR {
    param([string]$CIDR)
    $parts = $CIDR.Trim() -split '/'
    if ($parts.Count -ne 2) { return @() }
    $ipStr = $parts[0]
    $prefix = [int]$parts[1]
    $octets = $ipStr -split '\.'
    $ipInt = ([uint32]$octets[0] -shl 24) -bor ([uint32]$octets[1] -shl 16) -bor
             ([uint32]$octets[2] -shl 8)  -bor ([uint32]$octets[3])
    $mask = if ($prefix -eq 0) { [uint32]0 } else { ([uint32]::MaxValue) -shl (32 - $prefix) }
    $network = $ipInt -band $mask
    $broadcast = $network -bor (-bnot $mask -band [uint32]::MaxValue)
    $ips = [System.Collections.ArrayList]::new()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $o1 = ($i -shr 24) -band 0xFF
        $o2 = ($i -shr 16) -band 0xFF
        $o3 = ($i -shr 8)  -band 0xFF
        $o4 = $i -band 0xFF
        [void]$ips.Add("$o1.$o2.$o3.$o4")
    }
    return $ips
}

function Invoke-HostDiscovery {
    param(
        [string[]]$IPList,
        [int]$MaxThreads,
        [int]$TimeoutMs,
        [int[]]$PortList
    )

    Write-Log "Starting host discovery: $($IPList.Count) IPs, $MaxThreads threads"

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $pool.Open()
    $jobs = [System.Collections.ArrayList]::new()

    foreach ($ip in $IPList) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($IP, $Ports, $Timeout)
            $result = @{
                IP        = $IP
                Alive     = $false
                OpenPorts = @()
                Hostname  = ""
                OS        = ""
                TTL       = 0
            }
            # Ping
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $reply = $ping.Send($IP, $Timeout)
                if ($reply.Status -eq 'Success') {
                    $result.Alive = $true
                    $result.TTL = $reply.Options.Ttl
                }
                $ping.Dispose()
            } catch {}

            # Port scan
            foreach ($port in $Ports) {
                try {
                    $client = New-Object System.Net.Sockets.TcpClient
                    $ar = $client.BeginConnect($IP, $port, $null, $null)
                    $waited = $ar.AsyncWaitHandle.WaitOne($Timeout, $false)
                    if ($waited) {
                        try { $client.EndConnect($ar) } catch {}
                        $result.OpenPorts += $port
                        $result.Alive = $true
                    }
                    $client.Close()
                } catch { try { $client.Close() } catch {} }
            }

            # Reverse DNS
            if ($result.Alive) {
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($IP)
                    $result.Hostname = $dns.HostName
                } catch {}
            }

            # OS guess from TTL
            if ($result.TTL -gt 0) {
                if ($result.TTL -le 64) { $result.OS = "Linux/Unix" }
                elseif ($result.TTL -le 128) { $result.OS = "Windows" }
                elseif ($result.TTL -le 255) { $result.OS = "Network Device" }
            }

            return $result
        }).AddArgument($ip).AddArgument($PortList).AddArgument($TimeoutMs)

        $handle = $ps.BeginInvoke()
        [void]$jobs.Add(@{ PowerShell = $ps; Handle = $handle })
    }

    # Collect
    $liveHosts = [System.Collections.ArrayList]::new()
    $completed = 0
    foreach ($job in $jobs) {
        try {
            $r = $job.PowerShell.EndInvoke($job.Handle)
            if ($r -and $r.Count -gt 0 -and $r[0].Alive) {
                [void]$liveHosts.Add($r[0])
            }
        } catch {}
        $job.PowerShell.Dispose()
        $completed++
        if ($completed % 50 -eq 0) {
            Write-Host "`r  Discovered: $($liveHosts.Count) alive / $completed scanned of $($IPList.Count)   " -NoNewline -ForegroundColor Gray
        }
    }
    Write-Host "`r  Discovery complete: $($liveHosts.Count) alive hosts from $($IPList.Count) IPs scanned.     " -ForegroundColor Green

    $pool.Close()
    $pool.Dispose()

    return $liveHosts
}

# ============================================================
#  SCAN EXECUTION ENGINE (shared across all modes)
# ============================================================

function Invoke-PluginScan {
    <#
    .SYNOPSIS
        Runs selected plugins against a set of targets.
        Returns an array of finding hashtables.
    #>
    param(
        [array]$Targets,         # Array of @{ IP; Port; Hostname; ... }
        [array]$SelectedPlugins, # Array of validator hashtables
        [int]$MaxThreads,
        [int]$TimeoutMs
    )

    # Build test matrix: each target+port combination x each applicable plugin
    $testQueue = [System.Collections.ArrayList]::new()
    foreach ($target in $Targets) {
        foreach ($plugin in $SelectedPlugins) {
            $ports = @()
            if ($target.Port) {
                # Specific port provided (Validate or List mode)
                $ports = @($target.Port)
            } elseif ($plugin.ScanPorts -and $plugin.ScanPorts.Count -gt 0) {
                # Plugin declares which ports it wants to scan
                $ports = $plugin.ScanPorts
            } else {
                # Use target's open ports if available
                if ($target.OpenPorts) { $ports = $target.OpenPorts }
            }

            foreach ($port in $ports) {
                [void]$testQueue.Add(@{
                    IP         = $target.IP
                    Port       = $port
                    Hostname   = $target.Hostname
                    Plugin     = $plugin
                    PluginName = $plugin.Name
                })
            }
        }
    }

    if ($testQueue.Count -eq 0) {
        Write-Log "No test combinations to run." "WARN"
        return @()
    }

    Write-Log ("Running {0} tests ({1} targets x plugins) with {2} threads" -f $testQueue.Count, $Targets.Count, $MaxThreads)

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $pool.Open()
    $jobs = [System.Collections.ArrayList]::new()

    foreach ($test in $testQueue) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool

        $testBlockStr = $test.Plugin.TestBlock.ToString()

        [void]$ps.AddScript(@"
$($script:HelperFunctionsString)
`$testBlock = { $testBlockStr }
`$context = @{
    IP        = '$($test.IP)'
    Port      = '$($test.Port)'
    Hostname  = '$($test.Hostname)'
    TimeoutMs = $TimeoutMs
}
try {
    `$r = & `$testBlock `$context
    return @{
        IP         = '$($test.IP)'
        Port       = '$($test.Port)'
        Hostname   = '$($test.Hostname)'
        PluginName = '$($test.PluginName)'
        Result     = `$r.Result
        Detail     = `$r.Detail
    }
} catch {
    return @{
        IP         = '$($test.IP)'
        Port       = '$($test.Port)'
        Hostname   = '$($test.Hostname)'
        PluginName = '$($test.PluginName)'
        Result     = 'Error'
        Detail     = "Exception: `$(`$_.Exception.Message)"
    }
}
"@)

        $handle = $ps.BeginInvoke()
        [void]$jobs.Add(@{ PowerShell = $ps; Handle = $handle; Test = $test })
    }

    # Collect results
    $findings = [System.Collections.ArrayList]::new()
    $completed = 0
    foreach ($job in $jobs) {
        try {
            $output = $job.PowerShell.EndInvoke($job.Handle)
            if ($output -and $output.Count -gt 0) {
                $r = $output[0]
                [void]$findings.Add($r)

                $symbol = switch ($r.Result) {
                    "Remediated"   { "[FIXED]" }
                    "Vulnerable"   { "[VULN]" }
                    "Unreachable"  { "[DOWN]" }
                    "Error"        { "[ERR]" }
                    "Inconclusive" { "[???]" }
                    default        { "[---]" }
                }
                $color = switch ($r.Result) {
                    "Remediated"  { "Green" }
                    "Vulnerable"  { "Red" }
                    "Unreachable" { "DarkYellow" }
                    default       { "Gray" }
                }
                $completed++
                Write-Host ("  [{0}/{1}] {2,-8} {3}:{4} ({5}) -- {6}" -f `
                    $completed, $testQueue.Count, $symbol, $r.IP, $r.Port, $r.PluginName,
                    $(if ($r.Detail.Length -gt 80) { $r.Detail.Substring(0,77) + "..." } else { $r.Detail })
                ) -ForegroundColor $color
            }
        } catch {
            $completed++
        }
        $job.PowerShell.Dispose()
    }

    $pool.Close()
    $pool.Dispose()

    return $findings
}

# ============================================================
#  OUTPUT GENERATORS
# ============================================================

function Export-MasterCSV {
    param([array]$Findings, [string]$Path)
    $header = "IP,Hostname,Port,Plugin,Result,Detail,Timestamp"
    $lines = [System.Collections.ArrayList]::new()
    [void]$lines.Add($header)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    foreach ($f in $Findings) {
        $detail = ($f.Detail -replace '"', '""')
        if ($detail -match '[,"\n]') { $detail = "`"$detail`"" }
        $hostname = if ($f.Hostname) { $f.Hostname } else { "" }
        [void]$lines.Add("$($f.IP),$hostname,$($f.Port),$($f.PluginName),$($f.Result),$detail,$ts")
    }
    $lines -join "`n" | Out-File -FilePath $Path -Encoding UTF8
    Write-Log "Master CSV: $Path ($($Findings.Count) findings)"
}

function Export-SummaryReport {
    param([array]$Findings, [string]$Path, [string]$Mode)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("================================================================")
    [void]$sb.AppendLine("  ScottyScan Report")
    [void]$sb.AppendLine("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("  Mode: $Mode")
    [void]$sb.AppendLine("  Version: $($script:Version)")
    [void]$sb.AppendLine("================================================================")
    [void]$sb.AppendLine("")

    # Totals
    $total = $Findings.Count
    $vuln  = ($Findings | Where-Object { $_.Result -eq 'Vulnerable' }).Count
    $fixed = ($Findings | Where-Object { $_.Result -eq 'Remediated' }).Count
    $down  = ($Findings | Where-Object { $_.Result -eq 'Unreachable' }).Count
    $err   = ($Findings | Where-Object { $_.Result -eq 'Error' }).Count
    $inc   = ($Findings | Where-Object { $_.Result -eq 'Inconclusive' }).Count

    [void]$sb.AppendLine("SUMMARY")
    [void]$sb.AppendLine("-------")
    [void]$sb.AppendLine("  Total tests run:       $total")
    [void]$sb.AppendLine("  Vulnerable:            $vuln")
    [void]$sb.AppendLine("  Remediated/Clean:      $fixed")
    [void]$sb.AppendLine("  Unreachable:           $down")
    [void]$sb.AppendLine("  Errors:                $err")
    [void]$sb.AppendLine("  Inconclusive:          $inc")
    [void]$sb.AppendLine("")

    # By plugin
    [void]$sb.AppendLine("BY PLUGIN")
    [void]$sb.AppendLine("---------")
    $pluginGroups = $Findings | Group-Object { $_.PluginName }
    foreach ($pg in $pluginGroups) {
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("  [$($pg.Name)]")
        $subGroups = $pg.Group | Group-Object { $_.Result } | Sort-Object Name
        foreach ($sg in $subGroups) {
            [void]$sb.AppendLine(("    {0,-20} {1}" -f $sg.Name, $sg.Count))
        }
    }
    [void]$sb.AppendLine("")

    # Vulnerable findings detail
    $vulnFindings = $Findings | Where-Object { $_.Result -eq 'Vulnerable' }
    if ($vulnFindings.Count -gt 0) {
        [void]$sb.AppendLine("================================================================")
        [void]$sb.AppendLine("  VULNERABLE (action required)")
        [void]$sb.AppendLine("================================================================")
        foreach ($f in ($vulnFindings | Sort-Object { $_.IP })) {
            [void]$sb.AppendLine(("  {0,-18} {1,-35} port {2,-6} [{3}]" -f $f.IP, $f.Hostname, $f.Port, $f.PluginName))
            [void]$sb.AppendLine(("    {0}" -f $f.Detail))
        }
        [void]$sb.AppendLine("")
    }

    # Unreachable
    $downFindings = $Findings | Where-Object { $_.Result -eq 'Unreachable' }
    if ($downFindings.Count -gt 0) {
        [void]$sb.AppendLine("================================================================")
        [void]$sb.AppendLine("  UNREACHABLE")
        [void]$sb.AppendLine("================================================================")
        $downIPs = $downFindings | Select-Object IP, Hostname -Unique
        foreach ($d in $downIPs) {
            $ports = ($downFindings | Where-Object { $_.IP -eq $d.IP } | ForEach-Object { $_.Port } | Sort-Object -Unique) -join ', '
            [void]$sb.AppendLine(("  {0,-18} {1,-35} ports: {2}" -f $d.IP, $d.Hostname, $ports))
        }
        [void]$sb.AppendLine("")
    }

    # Remediated
    $fixedFindings = $Findings | Where-Object { $_.Result -eq 'Remediated' }
    if ($fixedFindings.Count -gt 0) {
        [void]$sb.AppendLine("================================================================")
        [void]$sb.AppendLine("  REMEDIATED / CLEAN")
        [void]$sb.AppendLine("================================================================")
        foreach ($f in ($fixedFindings | Sort-Object { $_.IP })) {
            [void]$sb.AppendLine(("  {0,-18} {1,-35} port {2,-6} [{3}]" -f $f.IP, $f.Hostname, $f.Port, $f.PluginName))
        }
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine("================================================================")
    [void]$sb.AppendLine("  END OF REPORT")
    [void]$sb.AppendLine("================================================================")

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
    Write-Log "Summary report: $Path"
}

function Export-DiscoveryCSV {
    param([array]$Hosts, [string]$Path)
    $header = "IP,Hostname,OS,TTL,OpenPorts"
    $lines = [System.Collections.ArrayList]::new()
    [void]$lines.Add($header)
    foreach ($h in $Hosts) {
        $ports = ($h.OpenPorts | Sort-Object) -join ';'
        [void]$lines.Add("$($h.IP),$($h.Hostname),$($h.OS),$($h.TTL),$ports")
    }
    $lines -join "`n" | Out-File -FilePath $Path -Encoding UTF8
    Write-Log "Discovery CSV: $Path ($($Hosts.Count) hosts)"
}

function Export-ValidateCSV {
    <#
    .SYNOPSIS
        For Validate mode: writes back the original OpenVAS CSV with validation columns appended.
    #>
    param([array]$OriginalRows, [hashtable]$ResultLookup, [string]$Path, [switch]$UpdateStatus)

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $outCols = @('Status','ip','hostname','port','protocol','cvss','severity','qod','nvt_name',
                 'Validation_Result','Validation_Detail','Validation_Plugin','Validation_Timestamp')

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine(($outCols -join ','))

    foreach ($row in $OriginalRows) {
        $normIP = (($row.ip.Trim() -split '\.') | ForEach-Object { [int]$_ }) -join '.'
        $key = "{0}:{1}" -f $normIP, $row.port

        $valResult = ""
        $valDetail = ""
        $valPlugin = ""
        $valTime   = ""

        if ($ResultLookup.ContainsKey($key)) {
            $r = $ResultLookup[$key]
            $valResult = $r.Result
            $valDetail = $r.Detail
            $valPlugin = $r.PluginName
            $valTime   = $ts

            if ($UpdateStatus) {
                if ($r.Result -eq "Remediated")  { $row.Status = "Remediated" }
                if ($r.Result -eq "Vulnerable")  { $row.Status = "Confirmed Vulnerable" }
            }
        }

        $values = @()
        foreach ($col in @('Status','ip','hostname','port','protocol','cvss','severity','qod','nvt_name')) {
            $v = $row.$col
            if ($v -match '[,"\n\r]') { $v = '"' + ($v -replace '"','""') + '"' }
            $values += $v
        }
        if ($valDetail -match '[,"\n\r]') { $valDetail = '"' + ($valDetail -replace '"','""') + '"' }
        $values += $valResult
        $values += $valDetail
        $values += $valPlugin
        $values += $valTime

        [void]$sb.AppendLine(($values -join ','))
    }

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8 -NoNewline
    Write-Log "Validated CSV: $Path"
}

# ============================================================
#  CSV PARSER (OpenVAS format, handles commas in nvt_name)
# ============================================================

function Import-OpenVASCSV {
    param([string]$Path)
    $lines = Get-Content -Path $Path -Encoding UTF8
    if ($lines.Count -lt 2) { return @() }
    $rows = [System.Collections.ArrayList]::new()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split ','
        if ($parts.Count -ge 9) {
            [void]$rows.Add([ordered]@{
                Status   = $parts[0]
                ip       = $parts[1]
                hostname = $parts[2]
                port     = $parts[3]
                protocol = $parts[4]
                cvss     = $parts[5]
                severity = $parts[6]
                qod      = $parts[7]
                nvt_name = ($parts[8..($parts.Count - 1)] -join ',')
            })
        }
    }
    return $rows
}

# ============================================================
#  MODE: NETWORK SCAN
# ============================================================

function Invoke-ScanMode {
    param(
        [string[]]$CIDRList,
        [array]$SelectedPlugins,
        [array]$SelectedOutputs,
        [int]$Threads,
        [int]$Timeout,
        [int[]]$PortList,
        [string]$OutDir
    )

    Write-Section "PHASE 1: Host Discovery"

    # Expand CIDRs
    $allIPs = [System.Collections.ArrayList]::new()
    foreach ($cidr in $CIDRList) {
        $ips = Expand-CIDR $cidr
        Write-Log "CIDR $cidr -> $($ips.Count) IPs"
        foreach ($ip in $ips) { [void]$allIPs.Add($ip) }
    }
    $uniqueIPs = $allIPs | Sort-Object -Unique
    Write-Log "Total unique IPs: $($uniqueIPs.Count)"

    $liveHosts = Invoke-HostDiscovery -IPList $uniqueIPs -MaxThreads $Threads -TimeoutMs $Timeout -PortList $PortList
    Write-Log "$($liveHosts.Count) live hosts discovered" "OK"

    # Export discovery CSV if requested
    if ($SelectedOutputs -contains "DiscoveryCSV") {
        $discPath = Join-Path $OutDir "Discovery_$($script:Timestamp).csv"
        Export-DiscoveryCSV -Hosts $liveHosts -Path $discPath
    }

    if ($liveHosts.Count -eq 0) {
        Write-Log "No live hosts found. Nothing to scan." "WARN"
        return
    }

    # Build targets from live hosts
    $targets = $liveHosts | ForEach-Object {
        @{
            IP        = $_.IP
            Hostname  = $_.Hostname
            OpenPorts = $_.OpenPorts
            OS        = $_.OS
            Port      = $null  # plugins will use OpenPorts or ScanPorts
        }
    }

    Write-Section "PHASE 2: Vulnerability Scanning"

    $findings = Invoke-PluginScan -Targets $targets -SelectedPlugins $SelectedPlugins `
                                  -MaxThreads $Threads -TimeoutMs $Timeout

    Write-Section "PHASE 3: Output"
    Export-Results -Findings $findings -SelectedOutputs $SelectedOutputs -OutDir $OutDir -Mode "Network Scan"
}

# ============================================================
#  MODE: LIST SCAN
# ============================================================

function Invoke-ListMode {
    param(
        [string]$HostFilePath,
        [array]$SelectedPlugins,
        [array]$SelectedOutputs,
        [int]$Threads,
        [int]$Timeout,
        [string]$OutDir
    )

    Write-Section "Loading Host List"

    $lines = Get-Content -Path $HostFilePath | Where-Object { $_ -match '\S' } |
             ForEach-Object { $_.Trim() }
    Write-Log "$($lines.Count) hosts loaded from $HostFilePath"

    $targets = $lines | ForEach-Object {
        @{
            IP        = $_
            Hostname  = ""
            OpenPorts = @()
            Port      = $null
        }
    }

    Write-Section "Vulnerability Scanning"

    $findings = Invoke-PluginScan -Targets $targets -SelectedPlugins $SelectedPlugins `
                                  -MaxThreads $Threads -TimeoutMs $Timeout

    Write-Section "Output"
    Export-Results -Findings $findings -SelectedOutputs $SelectedOutputs -OutDir $OutDir -Mode "List Scan"
}

# ============================================================
#  MODE: VALIDATE
# ============================================================

function Invoke-ValidateMode {
    param(
        [string]$CSVPath,
        [array]$SelectedPlugins,
        [array]$SelectedOutputs,
        [int]$Threads,
        [int]$Timeout,
        [string]$OutDir
    )

    Write-Section "Loading OpenVAS CSV"

    $rows = Import-OpenVASCSV -Path $CSVPath
    Write-Log "$($rows.Count) findings loaded"

    # Match each row to a validator
    $matchable = [System.Collections.ArrayList]::new()
    $noMatch = 0
    foreach ($row in $rows) {
        $v = Find-Validator -NVTName $row.nvt_name -Port $row.port -Protocol $row.protocol
        if ($v -and ($SelectedPlugins | Where-Object { $_.Name -eq $v.Name })) {
            [void]$matchable.Add(@{
                Row    = $row
                Plugin = $v
            })
        } else {
            $noMatch++
        }
    }

    Write-Log "$($matchable.Count) findings matched to selected plugins, $noMatch unmatched"

    # Build targets from matched findings
    $targets = $matchable | ForEach-Object {
        $normIP = (($_.Row.ip.Trim() -split '\.') | ForEach-Object { [int]$_ }) -join '.'
        @{
            IP       = $normIP
            Port     = $_.Row.port
            Hostname = $_.Row.hostname
        }
    }

    # Deduplicate test targets (same IP:Port:Plugin)
    $dedupedTargets = @{}
    $targetPluginMap = @{}
    for ($i = 0; $i -lt $matchable.Count; $i++) {
        $t = $targets[$i]
        $p = $matchable[$i].Plugin
        $key = "{0}:{1}:{2}" -f $t.IP, $t.Port, $p.Name
        if (-not $dedupedTargets.ContainsKey($key)) {
            $dedupedTargets[$key] = $t
            $targetPluginMap[$key] = $p
        }
    }

    Write-Log "$($dedupedTargets.Count) unique validation tests after dedup"

    Write-Section "Validating Findings"

    # Build plugin-specific target lists and run scans
    $allFindings = [System.Collections.ArrayList]::new()
    $uniquePlugins = $targetPluginMap.Values | Sort-Object { $_.Name } -Unique

    foreach ($plugin in $uniquePlugins) {
        $pluginTargets = @()
        foreach ($key in $dedupedTargets.Keys) {
            if ($targetPluginMap[$key].Name -eq $plugin.Name) {
                $pluginTargets += $dedupedTargets[$key]
            }
        }
        if ($pluginTargets.Count -gt 0) {
            $pFindings = Invoke-PluginScan -Targets $pluginTargets -SelectedPlugins @($plugin) `
                                           -MaxThreads $Threads -TimeoutMs $Timeout
            foreach ($pf in $pFindings) { [void]$allFindings.Add($pf) }
        }
    }

    # Build result lookup for CSV export
    $resultLookup = @{}
    foreach ($f in $allFindings) {
        $key = "{0}:{1}" -f $f.IP, $f.Port
        $resultLookup[$key] = $f
    }

    Write-Section "Output"

    # Always produce the validated CSV for validate mode
    $valCSVPath = Join-Path $OutDir "Validated_$($script:Timestamp).csv"
    Export-ValidateCSV -OriginalRows $rows -ResultLookup $resultLookup -Path $valCSVPath -UpdateStatus

    Export-Results -Findings $allFindings -SelectedOutputs $SelectedOutputs -OutDir $OutDir -Mode "Validate"
}

# ============================================================
#  OUTPUT DISPATCHER
# ============================================================

function Export-Results {
    param([array]$Findings, [array]$SelectedOutputs, [string]$OutDir, [string]$Mode)

    if ($SelectedOutputs -contains "MasterCSV") {
        $masterPath = Join-Path $OutDir "ScottyScan_Master_$($script:Timestamp).csv"
        Export-MasterCSV -Findings $Findings -Path $masterPath
    }

    if ($SelectedOutputs -contains "SummaryReport") {
        $reportPath = Join-Path $OutDir "ScottyScan_Report_$($script:Timestamp).txt"
        Export-SummaryReport -Findings $Findings -Path $reportPath -Mode $Mode
    }

    if ($SelectedOutputs -contains "PerPluginCSV") {
        $pluginGroups = $Findings | Group-Object { $_.PluginName }
        foreach ($pg in $pluginGroups) {
            $pPath = Join-Path $OutDir "ScottyScan_$($pg.Name)_$($script:Timestamp).csv"
            Export-MasterCSV -Findings $pg.Group -Path $pPath
        }
    }
}

# ============================================================
#  MAIN ENTRY POINT
# ============================================================

# --- Init ---
Load-Config

$outDir = if ($OutputDir) { $OutputDir } else { $script:Config.LastOutputDir }
if (-not $outDir) { $outDir = ".\output_reports" }
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$logDir = Join-Path $outDir "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$script:LogFile = Join-Path $logDir "ScottyScan_$($script:Timestamp).log"

Write-Banner

# --- Load plugins ---
$plugDir = if ($PluginDir) { $PluginDir } else { Join-Path $PSScriptRoot "plugins" }
Load-Plugins -Dir $plugDir

if ($script:Validators.Count -eq 0) {
    Write-Log "No plugins loaded. Place .ps1 plugin files in: $plugDir" "ERROR"
    exit 1
}

# --- Resolve threads/timeout ---
$threads = if ($MaxThreads -gt 0) { $MaxThreads } elseif ($script:Config.DefaultThreads) { $script:Config.DefaultThreads } else { 20 }
$timeout = if ($TimeoutMs -gt 0) { $TimeoutMs } elseif ($script:Config.DefaultTimeoutMs) { $script:Config.DefaultTimeoutMs } else { 5000 }

# --- Determine mode ---
$mode = ""
if ($Scan)     { $mode = "Scan" }
if ($List)     { $mode = "List" }
if ($Validate) { $mode = "Validate" }

if (-not $mode -and -not $NoMenu) {
    # Interactive mode selection
    $lastMode = $script:Config.LastMode
    $modeItems = @(
        @{ Name = "Network Scan"; Value = "Scan"; Selected = ($lastMode -eq "Scan"); Description = "Discover hosts on CIDRs and scan for vulnerabilities" }
        @{ Name = "List Scan";    Value = "List"; Selected = ($lastMode -eq "List"); Description = "Scan specific hosts from a file" }
        @{ Name = "Validate";     Value = "Validate"; Selected = ($lastMode -eq "Validate"); Description = "Validate OpenVAS findings against live hosts" }
    )
    # Default first item if nothing was last
    if (-not $lastMode) { $modeItems[0].Selected = $true }
    $modeResult = Show-CheckboxMenu -Title "What would you like to do?" -Items $modeItems -SingleSelect
    $mode = $modeResult | Select-Object -First 1
}

if (-not $mode) {
    Write-Log "No mode specified. Use -Scan, -List, or -Validate (or run without -NoMenu for interactive)." "ERROR"
    exit 1
}

Update-ConfigValue "LastMode" $mode
Write-Log "Mode: $mode"

# --- Plugin selection ---
$selectedPlugins = @()
if ($Plugins) {
    $pluginNames = $Plugins -split ','  | ForEach-Object { $_.Trim() }
    $selectedPlugins = $script:Validators | Where-Object { $pluginNames -contains $_.Name }
} elseif (-not $NoMenu) {
    $pluginItems = $script:Validators | ForEach-Object {
        $isDefault = ($script:Config.DefaultPlugins.Count -eq 0) -or ($script:Config.DefaultPlugins -contains $_.Name)
        @{
            Name        = $_.Name
            Value       = $_.Name
            Selected    = $isDefault
            Description = $_.Description
        }
    }
    $selectedNames = Show-CheckboxMenu -Title "Which plugins to run?" -Items $pluginItems -AllowSelectAll
    $selectedPlugins = $script:Validators | Where-Object { $selectedNames -contains $_.Name }
} else {
    $selectedPlugins = $script:Validators  # NoMenu = all plugins
}

if ($selectedPlugins.Count -eq 0) {
    Write-Log "No plugins selected." "ERROR"
    exit 1
}

Update-ConfigValue "DefaultPlugins" @($selectedPlugins | ForEach-Object { $_.Name })
Write-Log ("Plugins: {0}" -f (($selectedPlugins | ForEach-Object { $_.Name }) -join ', '))

# --- Output selection ---
$selectedOutputs = @()
if ($Outputs) {
    $selectedOutputs = $Outputs -split ',' | ForEach-Object { $_.Trim() }
} elseif (-not $NoMenu) {
    $outputItems = @(
        @{ Name = "Master findings CSV";       Value = "MasterCSV";       Selected = ($script:Config.DefaultOutputs -contains "MasterCSV");       Description = "All findings in one CSV" }
        @{ Name = "Executive summary report";  Value = "SummaryReport";   Selected = ($script:Config.DefaultOutputs -contains "SummaryReport");   Description = "Plain-text report for CAB/exec review" }
        @{ Name = "Per-plugin result CSVs";    Value = "PerPluginCSV";    Selected = ($script:Config.DefaultOutputs -contains "PerPluginCSV");    Description = "Separate CSV per plugin" }
        @{ Name = "Host discovery CSV";        Value = "DiscoveryCSV";    Selected = ($script:Config.DefaultOutputs -contains "DiscoveryCSV");    Description = "Live hosts with open ports and OS (Scan mode only)" }
    )
    $selectedOutputs = Show-CheckboxMenu -Title "Output options:" -Items $outputItems -AllowSelectAll
} else {
    $selectedOutputs = @("MasterCSV", "SummaryReport")
}

Update-ConfigValue "DefaultOutputs" $selectedOutputs
Update-ConfigValue "LastOutputDir" $outDir

# --- Mode-specific input gathering and execution ---
switch ($mode) {
    "Scan" {
        # Gather CIDRs
        $cidrList = @()
        if ($CIDRs) {
            $cidrList = $CIDRs -split ',' | ForEach-Object { $_.Trim() }
        } elseif ($CIDRFile -and (Test-Path $CIDRFile)) {
            $cidrList = Get-Content $CIDRFile | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
        } elseif (-not $NoMenu) {
            $cidrInput = Show-TextPrompt -Prompt "Enter CIDRs (comma-separated) or path to CIDR file:" `
                                         -LastValue $script:Config.LastCIDRs
            if (Test-Path $cidrInput -ErrorAction SilentlyContinue) {
                $cidrList = Get-Content $cidrInput | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
                Update-ConfigValue "LastCIDRFile" $cidrInput
            } else {
                $cidrList = $cidrInput -split ',' | ForEach-Object { $_.Trim() }
            }
            Update-ConfigValue "LastCIDRs" ($cidrList -join ', ')
        }

        if ($cidrList.Count -eq 0) {
            Write-Log "No CIDRs provided." "ERROR"
            exit 1
        }

        # Resolve ports
        $portStr = if ($Ports) { $Ports } else { $script:Config.DefaultPorts }
        if (-not $portStr) { $portStr = "22,80,135,443,445,3389" }
        $portList = $portStr -split ',' | ForEach-Object { [int]$_.Trim() }

        # Also add plugin-declared ScanPorts
        foreach ($p in $selectedPlugins) {
            if ($p.ScanPorts) {
                $portList += $p.ScanPorts
            }
        }
        $portList = $portList | Sort-Object -Unique

        Save-Config
        Invoke-ScanMode -CIDRList $cidrList -SelectedPlugins $selectedPlugins `
                        -SelectedOutputs $selectedOutputs -Threads $threads `
                        -Timeout $timeout -PortList $portList -OutDir $outDir
    }

    "List" {
        $hostFile = ""
        if ($HostFile -and (Test-Path $HostFile)) {
            $hostFile = $HostFile
        } elseif (-not $NoMenu) {
            $hostFile = Show-FilePrompt -Prompt "Host list file (one IP/hostname per line):" `
                                        -LastPath $script:Config.LastHostFile `
                                        -Filter "Text files (*.txt)|*.txt|All files (*.*)|*.*" `
                                        -MustExist
            Update-ConfigValue "LastHostFile" $hostFile
        }

        if (-not $hostFile -or -not (Test-Path $hostFile)) {
            Write-Log "No valid host file provided." "ERROR"
            exit 1
        }

        Save-Config
        Invoke-ListMode -HostFilePath $hostFile -SelectedPlugins $selectedPlugins `
                        -SelectedOutputs $selectedOutputs -Threads $threads `
                        -Timeout $timeout -OutDir $outDir
    }

    "Validate" {
        $csvPath = ""
        if ($InputCSV -and (Test-Path $InputCSV)) {
            $csvPath = $InputCSV
        } elseif (-not $NoMenu) {
            $csvPath = Show-FilePrompt -Prompt "OpenVAS CSV file:" `
                                       -LastPath $script:Config.LastInputCSV `
                                       -Filter "CSV files (*.csv)|*.csv|All files (*.*)|*.*" `
                                       -MustExist
            Update-ConfigValue "LastInputCSV" $csvPath
        }

        if (-not $csvPath -or -not (Test-Path $csvPath)) {
            Write-Log "No valid CSV file provided." "ERROR"
            exit 1
        }

        Save-Config
        Invoke-ValidateMode -CSVPath $csvPath -SelectedPlugins $selectedPlugins `
                            -SelectedOutputs $selectedOutputs -Threads $threads `
                            -Timeout $timeout -OutDir $outDir
    }
}

Save-Config
Write-Host ""
Write-Host "  ScottyScan complete." -ForegroundColor Green
Write-Host ""
