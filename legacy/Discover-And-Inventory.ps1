<#
.SYNOPSIS
    Discover-And-Inventory.ps1
    Network discovery, OS fingerprinting, and software inventory scanner.

.DESCRIPTION
    Phase 1 - Host Discovery: Scans CIDR ranges via ICMP echo + TCP port probes (445, 22, 3389)
              to find live hosts. Generates: LiveHosts_<timestamp>.csv
    Phase 2 - OS Fingerprinting: Identifies Windows vs Linux and version info using
              out-of-band techniques (WMI, SMB, SSH banner, TTL, open ports).
              Generates: HostInventory_<timestamp>.csv
    Phase 3 - Software Inventory: For Windows hosts, pulls installed software via Remote Registry
              and WMI (dual-source for completeness). Supports wildcard filtering.
              Generates: SoftwareInventory_<timestamp>.csv
    Phase 3b - Vulnerability Flagging: Flags software matching specified patterns whose versions
              fall outside a safe threshold. Generates per-app remediation CSVs and IP lists.

    Designed for incident-response scenarios (e.g. Notepad++ supply chain CVE-2025-15556)
    but fully generalised for any software search/flag across a mixed environment.

.PARAMETER CIDRs
    Comma-separated CIDR ranges, e.g. "192.168.1.0/24,10.0.0.0/16"

.PARAMETER CIDRFile
    Path to a text file with one CIDR per line.

.PARAMETER HostFile
    Skip discovery -- provide a file of known IPs/hostnames (one per line).

.PARAMETER SoftwareFilter
    Wildcard pattern(s) comma-separated for general inventory filtering.
    E.g. "*notepad*,*putty*,*7-zip*"
    This controls what appears in the FILTERED output CSV.

.PARAMETER SoftwareFilterFile
    Path to a text file with one wildcard pattern per line (general filtering).

.PARAMETER FlagFilter
    Comma-separated wildcard patterns for VULNERABILITY FLAGGING.
    Each position corresponds to the same position in -FlagVersion.
    E.g. "*notepad*,*putty*,*flash*"

.PARAMETER FlagVersion
    Comma-separated version thresholds for flagging. Uses text-based operators
    to avoid shell parsing issues with < and > characters:
      LT8.9.1   -- flag anything BELOW 8.9.1 (most common for CVE remediation)
      LE8.8.8   -- flag anything at or below 8.8.8
      GT0.0.0   -- flag ANY version found (existence check)
      GE0.0.0   -- flag ANY version found (existence check)
      EQ5.5.1   -- flag only exact version 5.5.1
      NE8.9.1   -- flag anything that is NOT 8.9.1
      *          -- flag ALL versions (wildcard, same as existence check)
    Operators are case-insensitive (LT, lt, Lt all work).
    Each position corresponds to the same position in -FlagFilter.
    E.g. "LT8.9.1,LT0.82,*"

    In flag rule FILES (-FlagFilterFile), symbol operators (<, <=, >, >=, =, !=)
    are also supported since file content is not subject to shell parsing.

.PARAMETER FlagFilterFile
    Path to a CSV or text file defining flag rules. Format (one rule per line):
      *notepad*,LT8.9.1,CVE-2025-15556 supply chain attack
      *putty*,LT0.82,CVE-2024-31497 ECDSA nonce bias
      *flash*,*,EOL -- remove immediately
    Columns: Pattern, VersionRule, Description (description is optional)
    Both text operators (LT, LE, GT, GE, EQ, NE) and symbol operators
    (<, <=, >, >=, =, !=) are accepted in rule files.

.PARAMETER FlagLabel
    Comma-separated labels/descriptions for each flag rule.
    E.g. "CVE-2025-15556,CVE-2024-31497,EOL software"

.PARAMETER Phase
    Which phases to run: "All" (default), "Discovery", "Fingerprint", "Software", or
    comma-separated like "Discovery,Fingerprint"

.PARAMETER OutputDir
    Output directory for all CSVs and logs. Default: .\output_reports

.PARAMETER MaxThreads
    Parallel thread count for scanning. Default: 50

.PARAMETER TimeoutMs
    Timeout in milliseconds for ping/port probes. Default: 1000

.PARAMETER Credential
    PSCredential object. If not provided, uses current domain credentials.

.PARAMETER Ports
    TCP ports to probe during discovery. Default: 445,22,3389,135,80

.EXAMPLE
    # Full scan with Notepad++ vulnerability flagging
    .\Discover-And-Inventory.ps1 -CIDRs "192.168.1.0/24,10.0.50.0/24" `
        -SoftwareFilter "*notepad*" `
        -FlagFilter "*notepad*" -FlagVersion "LT8.9.1" -FlagLabel "CVE-2025-15556"

.EXAMPLE
    # Multiple flag rules -- Notepad++ AND PuTTY AND Flash
    .\Discover-And-Inventory.ps1 -CIDRs "192.168.100.0/24" `
        -SoftwareFilter "*notepad*,*putty*,*flash*" `
        -FlagFilter "*notepad*,*putty*,*flash*" `
        -FlagVersion "LT8.9.1,LT0.82,*" `
        -FlagLabel "CVE-2025-15556 supply chain,CVE-2024-31497 ECDSA nonce,EOL remove immediately"

.EXAMPLE
    # Flag rules from a file (most flexible)
    .\Discover-And-Inventory.ps1 -CIDRs "192.168.100.0/24" -FlagFilterFile .\flag_rules.csv

.EXAMPLE
    # Discovery only, from a CIDR file
    .\Discover-And-Inventory.ps1 -CIDRFile .\cidrs.txt -Phase Discovery

.EXAMPLE
    # Software inventory on known hosts, general filter only (no flagging)
    .\Discover-And-Inventory.ps1 -HostFile .\hosts.txt -Phase Software -SoftwareFilter "*notepad*,*putty*,*7-zip*"

.NOTES
    Author:  Steven / InfoWerks Cybersecurity
    Version: 2.2.0
    Date:    2026-02-05
    Context: Generic vulnerability flagging engine with per-app version thresholds
#>

[CmdletBinding(DefaultParameterSetName = 'CIDR')]
param(
    [Parameter(ParameterSetName = 'CIDR')]
    [string]$CIDRs,

    [Parameter(ParameterSetName = 'CIDRFile')]
    [string]$CIDRFile,

    [Parameter(ParameterSetName = 'HostList')]
    [string]$HostFile,

    [string]$SoftwareFilter,
    [string]$SoftwareFilterFile,

    [string]$FlagFilter,
    [string]$FlagVersion,
    [string]$FlagLabel,
    [string]$FlagFilterFile,

    [ValidateSet("All","Discovery","Fingerprint","Software")]
    [string[]]$Phase = @("All"),

    [string]$OutputDir = ".\output_reports",
    [string]$LogDir    = ".\logs",
    [int]$MaxThreads   = 50,
    [int]$TimeoutMs    = 1000,

    [PSCredential]$Credential,

    [int[]]$Ports = @(445, 22, 3389, 135, 80)
)

# ============================================================================
#  SETUP
# ============================================================================
$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format "yyyyMMdd_HHmmss"

foreach ($dir in @($OutputDir, $LogDir)) {
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

$logFile = Join-Path $LogDir "Discover-And-Inventory_$ts.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    $entry | Out-File -FilePath $logFile -Append -Encoding UTF8
    switch ($Level) {
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "WARN"    { Write-Host $entry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry -ForegroundColor Cyan }
    }
}

$ScriptVersion = "2.2.0"
$ScriptBuild   = "2026-02-05T11:35:00"

Write-Log "========== Discover-And-Inventory.ps1 started =========="
Write-Log "Script version: $ScriptVersion  build: $ScriptBuild"
Write-Log "Phases requested: $($Phase -join ', ')"

# Determine which phases to run
$runDiscovery    = ($Phase -contains "All") -or ($Phase -contains "Discovery")
$runFingerprint  = ($Phase -contains "All") -or ($Phase -contains "Fingerprint")
$runSoftware     = ($Phase -contains "All") -or ($Phase -contains "Software")

# ============================================================================
#  VERSION COMPARISON ENGINE
# ============================================================================
function Compare-VersionStrings {
    <#
    .SYNOPSIS
        Compares two dotted version strings. Returns -1, 0, or 1.
        -1 = Current is LESS than Target
         0 = Equal
         1 = Current is GREATER than Target
    #>
    param([string]$Current, [string]$Target)

    if (-not $Current -or -not $Target) { return -1 }

    try {
        $cParts = $Current -split '\.' | ForEach-Object { [int]$_ }
        $tParts = $Target  -split '\.' | ForEach-Object { [int]$_ }

        $maxLen = [Math]::Max($cParts.Count, $tParts.Count)
        for ($i = 0; $i -lt $maxLen; $i++) {
            $c = if ($i -lt $cParts.Count) { $cParts[$i] } else { 0 }
            $t = if ($i -lt $tParts.Count) { $tParts[$i] } else { 0 }
            if ($c -lt $t) { return -1 }
            if ($c -gt $t) { return 1 }
        }
        return 0
    }
    catch { return -1 }
}

function Test-VersionAgainstRule {
    <#
    .SYNOPSIS
        Tests a version string against a flag rule expression.
        Text operators:   LT8.9.1  LE8.8.8  GT1.0  GE2.0  EQ5.5.1  NE8.9.1  *
        Symbol operators: <8.9.1   <=8.8.8  >1.0   >=2.0  =5.5.1   !=8.9.1  *
        Returns $true if the version IS FLAGGED (i.e., vulnerable/matching).
    #>
    param([string]$Version, [string]$Rule)

    $Rule = $Rule.Trim()

    # Wildcard -- flag everything
    if ($Rule -eq '*') { return $true }

    # No version on the host but rule expects one -- flag it (unknown = assume bad)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $true }

    # Parse operator and threshold -- try text operators first (case-insensitive),
    # then fall back to symbol operators for flag-rule-file compatibility.
    $operator = ''
    $threshold = ''

    if ($Rule -match '^(LE|GE|NE|LT|GT|EQ)(.+)$') {
        # Text-based operator (case-insensitive due to PowerShell default -match)
        $opText    = $Matches[1].ToUpper()
        $threshold = $Matches[2].Trim()
        $operator  = switch ($opText) {
            'LT' { '<'  }
            'LE' { '<=' }
            'GT' { '>'  }
            'GE' { '>=' }
            'EQ' { '='  }
            'NE' { '!=' }
        }
    }
    elseif ($Rule -match '^(<=|>=|!=|<|>|=)(.+)$') {
        # Symbol-based operator (supported in flag rule files)
        $operator  = $Matches[1]
        $threshold = $Matches[2].Trim()
    }
    else {
        # No operator -- treat as "less than" (most common remediation case)
        $operator  = '<'
        $threshold = $Rule
    }

    $cmp = Compare-VersionStrings -Current $Version -Target $threshold

    switch ($operator) {
        '<'  { return ($cmp -lt 0) }
        '<=' { return ($cmp -le 0) }
        '>'  { return ($cmp -gt 0) }
        '>=' { return ($cmp -ge 0) }
        '='  { return ($cmp -eq 0) }
        '!=' { return ($cmp -ne 0) }
        default { return $false }
    }
}

function Get-VersionStatus {
    <#
    .SYNOPSIS
        Returns a human-readable status string for a version against a rule.
    #>
    param([string]$Version, [string]$Rule)

    if ([string]::IsNullOrWhiteSpace($Version)) {
        return "NO VERSION - FLAGGED (assume vulnerable)"
    }

    $isFlagged = Test-VersionAgainstRule -Version $Version -Rule $Rule

    if ($isFlagged) {
        return "*** FLAGGED *** (v$Version matches rule: $Rule)"
    }
    else {
        return "OK (v$Version passes rule: $Rule)"
    }
}

# ============================================================================
#  FLAG RULE PARSER
# ============================================================================
# Build an array of flag rule objects from the various input methods.
# Each rule: @{ Pattern = "*notepad*"; VersionRule = "LT8.9.1"; Label = "CVE-..." }

$flagRules = [System.Collections.Generic.List[PSObject]]::new()

# Method 1: From file (CSV-style: pattern,versionrule,label)
if ($FlagFilterFile -and (Test-Path $FlagFilterFile)) {
    $flagLines = Get-Content -Path $FlagFilterFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' }
    foreach ($line in $flagLines) {
        $cols = $line -split ',' | ForEach-Object { $_.Trim() }
        if ($cols.Count -ge 2) {
            $flagRules.Add([PSCustomObject]@{
                Pattern     = $cols[0]
                VersionRule = $cols[1]
                Label       = if ($cols.Count -ge 3) { ($cols[2..($cols.Count-1)] -join ',').Trim() } else { "" }
            })
        }
    }
    Write-Log "Loaded $($flagRules.Count) flag rules from $FlagFilterFile"
}

# Method 2: From command-line parameters (positional correspondence)
if ($FlagFilter) {
    $fPatterns = @($FlagFilter  -split ',' | ForEach-Object { $_.Trim() })
    $fVersions = @(if ($FlagVersion) { $FlagVersion -split ',' | ForEach-Object { $_.Trim() } } else { @() })
    $fLabels   = @(if ($FlagLabel)   { $FlagLabel   -split ',' | ForEach-Object { $_.Trim() } } else { @() })

    for ($i = 0; $i -lt $fPatterns.Count; $i++) {
        $vRule = if ($i -lt $fVersions.Count) { $fVersions[$i] } else { "*" }
        $lbl   = if ($i -lt $fLabels.Count)   { $fLabels[$i] }   else { "" }
        $flagRules.Add([PSCustomObject]@{
            Pattern     = $fPatterns[$i]
            VersionRule = $vRule
            Label       = $lbl
        })
    }
}

if ($flagRules.Count -gt 0) {
    Write-Log "Flag rules ($($flagRules.Count)):"
    foreach ($rule in $flagRules) {
        $labelStr = if ($rule.Label) { " [$($rule.Label)]" } else { "" }
        Write-Log "  $($rule.Pattern)  version: $($rule.VersionRule)$labelStr"
    }
}

# ============================================================================
#  CIDR EXPANSION
# ============================================================================
function ConvertFrom-CIDR {
    <#
    .SYNOPSIS
        Expands a CIDR notation into an array of individual IP addresses.
        Excludes network and broadcast addresses for /24 and smaller.
    #>
    param([string]$CIDR)

    if ($CIDR -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') {
        Write-Log "Invalid CIDR format: $CIDR" "ERROR"
        return @()
    }

    $ipStr  = $Matches[1]
    $prefix = [int]$Matches[2]

    if ($prefix -lt 16 -or $prefix -gt 32) {
        Write-Log "CIDR prefix /$prefix out of safe range (16-32). Skipping $CIDR" "WARN"
        return @()
    }

    $ipBytes  = [System.Net.IPAddress]::Parse($ipStr).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt    = [BitConverter]::ToUInt32($ipBytes, 0)

    $hostBits = 32 - $prefix
    $numHosts = [Math]::Pow(2, $hostBits)
    $netAddr  = $ipInt -band ([UInt32]::MaxValue -shl $hostBits)

    $ips = [System.Collections.Generic.List[string]]::new()

    # For /31 and /32, return as-is
    if ($prefix -ge 31) {
        for ($i = 0; $i -lt $numHosts; $i++) {
            $addr = $netAddr + $i
            $bytes = [BitConverter]::GetBytes([UInt32]$addr)
            [Array]::Reverse($bytes)
            $ips.Add(([System.Net.IPAddress]::new($bytes)).ToString())
        }
    }
    else {
        # Skip network (.0) and broadcast (.255 for /24, etc.)
        for ($i = 1; $i -lt ($numHosts - 1); $i++) {
            $addr = $netAddr + $i
            $bytes = [BitConverter]::GetBytes([UInt32]$addr)
            [Array]::Reverse($bytes)
            $ips.Add(([System.Net.IPAddress]::new($bytes)).ToString())
        }
    }

    return $ips
}

# ============================================================================
#  PARALLEL EXECUTION ENGINE (RunspacePool)
# ============================================================================
function Invoke-Parallel {
    <#
    .SYNOPSIS
        Executes a scriptblock against an array of items using a RunspacePool
        for high-performance parallel scanning.
    #>
    param(
        [array]$InputList,
        [scriptblock]$ScriptBlock,
        [int]$Throttle = $MaxThreads,
        [hashtable]$SharedParams = @{}
    )

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Throttle, $iss, $Host)
    $pool.Open()

    $jobs = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($item in $InputList) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScriptBlock)
        [void]$ps.AddArgument($item)
        foreach ($key in $SharedParams.Keys) {
            [void]$ps.AddArgument($SharedParams[$key])
        }
        $handle = $ps.BeginInvoke()
        $jobs.Add([PSCustomObject]@{
            PowerShell = $ps
            Handle     = $handle
            Input      = $item
        })
    }

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $total = $jobs.Count
    $completed = 0

    foreach ($job in $jobs) {
        try {
            $output = $job.PowerShell.EndInvoke($job.Handle)
            if ($output) {
                foreach ($o in $output) { $results.Add($o) }
            }
        }
        catch {
            Write-Log "Parallel job failed for $($job.Input): $_" "ERROR"
        }
        finally {
            $job.PowerShell.Dispose()
        }
        $completed++
        if ($completed % 50 -eq 0 -or $completed -eq $total) {
            Write-Progress -Activity "Parallel Scan" -Status "$completed / $total" -PercentComplete (($completed / $total) * 100)
        }
    }

    Write-Progress -Activity "Parallel Scan" -Completed
    $pool.Close()
    $pool.Dispose()

    return $results
}

# ============================================================================
#  PHASE 1: HOST DISCOVERY
# ============================================================================
function Invoke-HostDiscovery {
    param([string[]]$TargetIPs)

    Write-Log "PHASE 1: Host Discovery -- $($TargetIPs.Count) IPs to scan"

    $discoveryBlock = {
        param($IP, $TimeoutMs, $Ports)

        $result = [PSCustomObject]@{
            IPAddress  = $IP
            Alive      = $false
            Method     = ""
            OpenPorts  = ""
            Hostname   = ""
        }

        # Method 1: ICMP Ping
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($IP, $TimeoutMs)
            if ($reply.Status -eq 'Success') {
                $result.Alive  = $true
                $result.Method = "ICMP (TTL=$($reply.Options.Ttl))"
            }
            $ping.Dispose()
        }
        catch { }

        # Method 2: TCP Port Probes (even if ping succeeded -- we want open port data)
        $openPorts = [System.Collections.Generic.List[int]]::new()
        foreach ($port in $Ports) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $task = $tcp.ConnectAsync($IP, $port)
                if ($task.Wait($TimeoutMs)) {
                    if ($tcp.Connected) {
                        $openPorts.Add($port)
                        if (-not $result.Alive) {
                            $result.Alive  = $true
                            $result.Method = "TCP:$port"
                        }
                    }
                }
                $tcp.Close()
                $tcp.Dispose()
            }
            catch { }
        }
        $result.OpenPorts = ($openPorts -join ";")

        # Reverse DNS
        if ($result.Alive) {
            try {
                $dns = [System.Net.Dns]::GetHostEntry($IP)
                $result.Hostname = $dns.HostName
            }
            catch { }
        }

        if ($result.Alive) { return $result }
    }

    $sharedParams = @{
        TimeoutMs = $TimeoutMs
        Ports     = $Ports
    }

    $liveHosts = Invoke-Parallel -InputList $TargetIPs -ScriptBlock $discoveryBlock -SharedParams $sharedParams

    $discoveryFile = Join-Path $OutputDir "LiveHosts_$ts.csv"
    if ($liveHosts -and $liveHosts.Count -gt 0) {
        $liveHosts | Sort-Object { [System.Version]($_.IPAddress -replace '(\d+)','00$1' -replace '0*(\d{3})','$1') } |
            Export-Csv -Path $discoveryFile -NoTypeInformation -Encoding UTF8
        Write-Log "Phase 1 complete: $($liveHosts.Count) live hosts found. Output: $discoveryFile" "SUCCESS"
    }
    else {
        Write-Log "Phase 1 complete: No live hosts found." "WARN"
    }

    return $liveHosts
}

# ============================================================================
#  PHASE 2: OS FINGERPRINTING
# ============================================================================
function Invoke-OSFingerprint {
    param([array]$LiveHosts, [PSCredential]$Credential)

    Write-Log "PHASE 2: OS Fingerprinting -- $($LiveHosts.Count) hosts"

    $fingerprintBlock = {
        param($HostObj, $Credential)

        $ip       = $HostObj.IPAddress
        $hostname = $HostObj.Hostname
        $ports    = $HostObj.OpenPorts -split ";"

        $result = [PSCustomObject]@{
            IPAddress     = $ip
            Hostname      = $hostname
            OSType        = 'Unknown'
            OSVersion     = ''
            OSBuild       = ''
            Domain        = ''
            DetectMethod  = ''
            OpenPorts     = $HostObj.OpenPorts
            Alive         = $true
            LastSeen      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }

        # --- Technique 1: WMI/CIM (best for Windows) ---
        $wmiSuccess = $false
        if ($ports -contains "135" -or $ports -contains "445") {
            try {
                $cimParams = @{
                    ComputerName  = $ip
                    ClassName     = 'Win32_OperatingSystem'
                    ErrorAction   = 'Stop'
                }
                if ($Credential) { $cimParams.Credential = $Credential }

                # Try CIM first (WinRM/DCOM)
                $os = Get-CimInstance @cimParams
                if ($os) {
                    $result.OSType       = 'Windows'
                    $result.OSVersion    = $os.Caption
                    $result.OSBuild      = $os.BuildNumber
                    $result.DetectMethod = 'CIM/WMI'
                    $wmiSuccess = $true

                    # Get domain
                    try {
                        $csParams = @{
                            ComputerName = $ip
                            ClassName    = 'Win32_ComputerSystem'
                            ErrorAction  = 'Stop'
                        }
                        if ($Credential) { $csParams.Credential = $Credential }
                        $cs = Get-CimInstance @csParams
                        $result.Domain = $cs.Domain
                    }
                    catch { }
                }
            }
            catch {
                # WMI failed -- could be Linux, or firewall blocking
            }
        }

        # --- Technique 2: SSH Banner Grab (Linux/ESXi) ---
        if (-not $wmiSuccess -and ($ports -contains "22")) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $task = $tcp.ConnectAsync($ip, 22)
                if ($task.Wait(3000) -and $tcp.Connected) {
                    $stream = $tcp.GetStream()
                    $stream.ReadTimeout = 3000
                    $buffer = New-Object byte[] 1024
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead).Trim()

                    $result.DetectMethod = 'SSH-Banner'

                    if ($banner -match 'Ubuntu') {
                        $result.OSType    = 'Linux'
                        $result.OSVersion = 'Ubuntu'
                        if ($banner -match 'Ubuntu[_-]?(\S+)') { $result.OSVersion = "Ubuntu $($Matches[1])" }
                    }
                    elseif ($banner -match 'Debian') {
                        $result.OSType    = 'Linux'
                        $result.OSVersion = 'Debian'
                    }
                    elseif ($banner -match 'CentOS|Red Hat|RHEL') {
                        $result.OSType    = 'Linux'
                        $result.OSVersion = $Matches[0]
                    }
                    elseif ($banner -match 'VMware|ESXi') {
                        $result.OSType    = 'VMware/ESXi'
                        $result.OSVersion = $banner -replace 'SSH-2.0-',''
                    }
                    elseif ($banner -match 'OpenSSH') {
                        # Could be Linux or Windows OpenSSH
                        if ($ports -contains "445" -or $ports -contains "3389") {
                            $result.OSType    = 'Windows (SSH)'
                            $result.OSVersion = $banner -replace 'SSH-2.0-',''
                        }
                        else {
                            $result.OSType    = 'Linux'
                            $result.OSVersion = $banner -replace 'SSH-2.0-',''
                        }
                    }
                    else {
                        $result.OSType    = 'Linux/Unix'
                        $result.OSVersion = $banner -replace 'SSH-2.0-',''
                    }
                }
                $tcp.Close()
                $tcp.Dispose()
            }
            catch { }
        }

        # --- Technique 3: SMB Signing / NetBIOS (Windows confirmation) ---
        if ($result.OSType -eq 'Unknown' -and ($ports -contains "445")) {
            $result.OSType       = 'Windows (probable)'
            $result.DetectMethod = 'Port-445-Open'
        }

        # --- Technique 4: TTL heuristic (fallback) ---
        if ($result.OSType -eq 'Unknown') {
            try {
                $ping2 = New-Object System.Net.NetworkInformation.Ping
                $r2 = $ping2.Send($ip, 2000)
                if ($r2.Status -eq 'Success' -and $r2.Options) {
                    $ttl = $r2.Options.Ttl
                    if ($ttl -le 64) {
                        $result.OSType       = "Linux/Unix (TTL=$ttl)"
                        $result.DetectMethod = 'TTL-Heuristic'
                    }
                    elseif ($ttl -le 128) {
                        $result.OSType       = "Windows (TTL=$ttl)"
                        $result.DetectMethod = 'TTL-Heuristic'
                    }
                }
                $ping2.Dispose()
            }
            catch { }
        }

        return $result
    }

    $sharedParams = @{ Credential = $Credential }
    $inventory = Invoke-Parallel -InputList $LiveHosts -ScriptBlock $fingerprintBlock -Throttle ([Math]::Min($MaxThreads, 20)) -SharedParams $sharedParams

    $inventoryFile = Join-Path $OutputDir "HostInventory_$ts.csv"
    if ($inventory -and $inventory.Count -gt 0) {
        $inventory | Sort-Object OSType, IPAddress |
            Export-Csv -Path $inventoryFile -NoTypeInformation -Encoding UTF8
        Write-Log "Phase 2 complete: $($inventory.Count) hosts fingerprinted. Output: $inventoryFile" "SUCCESS"

        # Summary
        $windowsCount = ($inventory | Where-Object { $_.OSType -like "Windows*" }).Count
        $linuxCount   = ($inventory | Where-Object { $_.OSType -like "Linux*" }).Count
        $esxiCount    = ($inventory | Where-Object { $_.OSType -like "VMware*" }).Count
        $unknownCount = ($inventory | Where-Object { $_.OSType -like "Unknown*" }).Count
        Write-Log ("  Windows: {0} // Linux: {1} // VMware: {2} // Unknown: {3}" -f $windowsCount, $linuxCount, $esxiCount, $unknownCount)
    }
    else {
        Write-Log "Phase 2 complete: No hosts fingerprinted." "WARN"
    }

    return $inventory
}

# ============================================================================
#  PHASE 3: SOFTWARE INVENTORY
# ============================================================================
function Get-SoftwareFromRegistry {
    <# Remote Registry method (from your original script, enhanced) #>
    param([string]$ComputerName, [string]$LogFile)

    $baseKeys = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($key in $baseKeys) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $sub = $reg.OpenSubKey($key)
            if ($null -eq $sub) { continue }

            foreach ($name in $sub.GetSubKeyNames()) {
                try {
                    $app  = $sub.OpenSubKey($name)
                    $disp = $app.GetValue("DisplayName")
                    if ([string]::IsNullOrWhiteSpace($disp)) { continue }

                    $results.Add([PSCustomObject]@{
                        ComputerName   = $ComputerName
                        Name           = $disp
                        Version        = $app.GetValue("DisplayVersion")
                        Publisher      = $app.GetValue("Publisher")
                        InstallDate    = $app.GetValue("InstallDate")
                        InstallPath    = $app.GetValue("InstallLocation")
                        UninstallCmd   = $app.GetValue("UninstallString")
                        Architecture   = if ($key -like "*WOW6432*") { "x86" } else { "x64" }
                        Source         = "Registry"
                        RegistryPath   = "HKLM:\$key\$name"
                    })
                }
                catch { }
            }
            $reg.Close()
        }
        catch {
            "[$ComputerName] Registry failed for $key : $_" | Out-File -FilePath $LogFile -Append
        }
    }
    return $results
}

function Get-SoftwareFromWMI {
    <# WMI/CIM fallback -- catches MSI-installed software that registry misses #>
    param([string]$ComputerName, [PSCredential]$Credential, [string]$LogFile)

    $results = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $cimParams = @{
            ComputerName = $ComputerName
            ClassName    = "Win32_Product"
            ErrorAction  = "Stop"
        }
        if ($Credential) { $cimParams.Credential = $Credential }

        $products = Get-CimInstance @cimParams
        foreach ($p in $products) {
            if ([string]::IsNullOrWhiteSpace($p.Name)) { continue }
            $results.Add([PSCustomObject]@{
                ComputerName   = $ComputerName
                Name           = $p.Name
                Version        = $p.Version
                Publisher      = $p.Vendor
                InstallDate    = $p.InstallDate
                InstallPath    = $p.InstallLocation
                UninstallCmd   = ""
                Architecture   = ""
                Source         = "WMI"
                RegistryPath   = ""
            })
        }
    }
    catch {
        "[$ComputerName] WMI query failed: $_" | Out-File -FilePath $LogFile -Append
    }
    return $results
}

function Get-SoftwareFromPSExec {
    <# PSRemoting fallback -- reads registry locally via Invoke-Command #>
    param([string]$ComputerName, [PSCredential]$Credential, [string]$LogFile)

    $results = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $invokeParams = @{
            ComputerName = $ComputerName
            ErrorAction  = "Stop"
            ScriptBlock  = {
                $output = [System.Collections.Generic.List[PSObject]]::new()
                $paths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                foreach ($path in $paths) {
                    try {
                        Get-ItemProperty $path -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName } |
                            ForEach-Object {
                                $output.Add([PSCustomObject]@{
                                    Name         = $_.DisplayName
                                    Version      = $_.DisplayVersion
                                    Publisher    = $_.Publisher
                                    InstallDate  = $_.InstallDate
                                    InstallPath  = $_.InstallLocation
                                    UninstallCmd = $_.UninstallString
                                    Architecture = if ($path -like "*WOW6432*") { "x86" } else { "x64" }
                                })
                            }
                    }
                    catch { }
                }
                return $output
            }
        }
        if ($Credential) { $invokeParams.Credential = $Credential }

        $remote = Invoke-Command @invokeParams
        foreach ($r in $remote) {
            $results.Add([PSCustomObject]@{
                ComputerName   = $ComputerName
                Name           = $r.Name
                Version        = $r.Version
                Publisher      = $r.Publisher
                InstallDate    = $r.InstallDate
                InstallPath    = $r.InstallPath
                UninstallCmd   = $r.UninstallCmd
                Architecture   = $r.Architecture
                Source         = "PSRemoting"
                RegistryPath   = ""
            })
        }
    }
    catch {
        "[$ComputerName] PSRemoting failed: $_" | Out-File -FilePath $LogFile -Append
    }
    return $results
}

function Invoke-SoftwareInventory {
    param(
        [array]$HostInventory,
        [string[]]$Filters,
        [array]$FlagRules,
        [PSCredential]$Credential
    )

    # Only scan Windows hosts
    $windowsHosts = $HostInventory | Where-Object { $_.OSType -like "Windows*" }

    if (-not $windowsHosts -or $windowsHosts.Count -eq 0) {
        Write-Log "Phase 3: No Windows hosts to scan for software." "WARN"
        return @()
    }

    Write-Log "PHASE 3: Software Inventory -- $($windowsHosts.Count) Windows hosts"
    if ($Filters) { Write-Log "  Filters: $($Filters -join ', ')" }

    $allSoftware = [System.Collections.Generic.List[PSObject]]::new()
    $counter = 0

    foreach ($host_ in $windowsHosts) {
        $counter++
        $ip = $host_.IPAddress
        $pct = [math]::Round(($counter / $windowsHosts.Count) * 100)
        Write-Progress -Activity "Software Inventory" -Status "$ip ($counter/$($windowsHosts.Count))" -PercentComplete $pct

        Write-Log "  Scanning $ip ($($host_.Hostname))..."

        # Try methods in order of preference: Registry -> PSRemoting -> WMI
        $hostSoftware = @()

        # Method 1: Remote Registry (fastest, least overhead)
        $hostSoftware = Get-SoftwareFromRegistry -ComputerName $ip -LogFile $logFile
        $method = "Registry"

        # Method 2: PSRemoting fallback
        if ($hostSoftware.Count -eq 0) {
            $hostSoftware = Get-SoftwareFromPSExec -ComputerName $ip -Credential $Credential -LogFile $logFile
            $method = "PSRemoting"
        }

        # Method 3: WMI fallback (slower, but catches some MSI-only installs)
        # NOTE: Win32_Product is slow and can trigger MSI reconfiguration. Use sparingly.
        if ($hostSoftware.Count -eq 0) {
            Write-Log "    Registry + PSRemoting failed for $ip -- falling back to WMI (slow)" "WARN"
            $hostSoftware = Get-SoftwareFromWMI -ComputerName $ip -Credential $Credential -LogFile $logFile
            $method = "WMI"
        }

        if ($hostSoftware.Count -gt 0) {
            Write-Log "    Found $($hostSoftware.Count) software entries via $method"
        }
        else {
            Write-Log "    No software retrieved from $ip (all methods failed)" "WARN"
        }

        # Deduplicate by Name+Version (registry and WMI can overlap)
        $hostSoftware = $hostSoftware | Sort-Object Name, Version -Unique

        foreach ($sw in $hostSoftware) { $allSoftware.Add($sw) }
    }

    Write-Progress -Activity "Software Inventory" -Completed

    # Apply general filters if specified (for the FILTERED csv)
    $filtered = $allSoftware
    if ($Filters -and $Filters.Count -gt 0) {
        $filtered = $allSoftware | Where-Object {
            $name = $_.Name
            $matchesAny = $false
            foreach ($f in $Filters) {
                if ($name -like $f) { $matchesAny = $true; break }
            }
            $matchesAny
        }

        Write-Log "  Filter matched $($filtered.Count) of $($allSoftware.Count) total entries"
    }

    # Export ALL software
    $allSoftwareFile = Join-Path $OutputDir "SoftwareInventory_ALL_$ts.csv"
    if ($allSoftware.Count -gt 0) {
        $allSoftware | Sort-Object ComputerName, Name |
            Export-Csv -Path $allSoftwareFile -NoTypeInformation -Encoding UTF8
        Write-Log "  Full inventory: $allSoftwareFile ($($allSoftware.Count) entries)" "SUCCESS"
    }

    # Export FILTERED results
    if ($Filters -and $filtered.Count -gt 0) {
        $filteredFile = Join-Path $OutputDir "SoftwareInventory_FILTERED_$ts.csv"
        $filtered | Sort-Object ComputerName, Name, Version |
            Export-Csv -Path $filteredFile -NoTypeInformation -Encoding UTF8
        Write-Log "  Filtered inventory: $filteredFile ($($filtered.Count) entries)" "SUCCESS"
    }

    # =========================================================================
    #  PHASE 3b: VULNERABILITY FLAGGING (generic, multi-app)
    # =========================================================================
    if ($FlagRules -and $FlagRules.Count -gt 0) {
        Write-Log ""
        Write-Log "  ================================================================" "WARN"
        Write-Log "  VULNERABILITY FLAGGING -- $($FlagRules.Count) rule(s) active" "WARN"
        Write-Log "  ================================================================" "WARN"

        # Master list of all flagged entries across all rules
        $allFlagged = [System.Collections.Generic.List[PSObject]]::new()

        foreach ($rule in $FlagRules) {
            $rulePattern = $rule.Pattern
            $ruleVersion = $rule.VersionRule
            $ruleLabel   = $rule.Label

            $labelDisplay = if ($ruleLabel) { " -- $ruleLabel" } else { "" }
            Write-Log ""
            Write-Log "  [RULE] $rulePattern  version: $ruleVersion$labelDisplay" "WARN"

            # Find all software matching this flag pattern
            $matchingEntries = $allSoftware | Where-Object { $_.Name -like $rulePattern }

            if (-not $matchingEntries -or @($matchingEntries).Count -eq 0) {
                Write-Log "    No installations found matching '$rulePattern'" "SUCCESS"
                Write-Log "    (clean)" "SUCCESS"
                continue
            }

            $flaggedCount = 0
            $okCount      = 0

            foreach ($entry in $matchingEntries) {
                $verStr    = $entry.Version
                $isFlagged = Test-VersionAgainstRule -Version $verStr -Rule $ruleVersion
                $statusMsg = Get-VersionStatus -Version $verStr -Rule $ruleVersion

                $logLine = "    {0} // {1} // {2}" -f $entry.ComputerName, $entry.Name, $statusMsg

                if ($isFlagged) {
                    $flaggedCount++
                    Write-Log $logLine "ERROR"

                    # Add to master flagged list with rule metadata
                    $allFlagged.Add([PSCustomObject]@{
                        ComputerName   = $entry.ComputerName
                        SoftwareName   = $entry.Name
                        Version        = $verStr
                        Architecture   = $entry.Architecture
                        InstallPath    = $entry.InstallPath
                        FlagRule       = $ruleVersion
                        FlagPattern    = $rulePattern
                        FlagLabel      = $ruleLabel
                        Status         = "FLAGGED"
                    })
                }
                else {
                    $okCount++
                    Write-Log $logLine "SUCCESS"
                }
            }

            Write-Log "    Summary: $flaggedCount flagged, $okCount OK out of $(@($matchingEntries).Count) instances"

            # Generate per-rule remediation files
            $ruleFlagged = $allFlagged | Where-Object { $_.FlagPattern -eq $rulePattern -and $_.FlagRule -eq $ruleVersion }
            if ($ruleFlagged -and @($ruleFlagged).Count -gt 0) {
                # Sanitize the pattern for use as a filename
                $safeName = ($rulePattern -replace '[\\/*?<>|":]','_' -replace '^\*','').Trim('_*. ')
                if (-not $safeName) { $safeName = "rule$($FlagRules.IndexOf($rule))" }

                $remediationFile = Join-Path $OutputDir "FLAGGED_${safeName}_TARGETS_$ts.csv"
                $ruleFlagged | Select-Object ComputerName, SoftwareName, Version, Architecture, InstallPath, FlagRule, FlagLabel |
                    Export-Csv -Path $remediationFile -NoTypeInformation -Encoding UTF8

                # IP list for the deployment script
                $ipListFile = Join-Path $OutputDir "FLAGGED_${safeName}_IPs_$ts.txt"
                (@($ruleFlagged) | Select-Object -ExpandProperty ComputerName -Unique) |
                    Out-File -FilePath $ipListFile -Encoding UTF8

                Write-Log "    Remediation CSV : $remediationFile" "WARN"
                Write-Log "    IP List         : $ipListFile" "WARN"
                Write-Log "    Feed the IP list to Deploy-SoftwareUpdate.ps1 for automated patching." "WARN"
            }
            else {
                Write-Log "    No flagged instances -- all OK!" "SUCCESS"
            }
        }

        # Master flagged CSV (all rules combined)
        if ($allFlagged.Count -gt 0) {
            $masterFlagFile = Join-Path $OutputDir "FLAGGED_ALL_TARGETS_$ts.csv"
            $allFlagged | Sort-Object FlagPattern, ComputerName, SoftwareName |
                Export-Csv -Path $masterFlagFile -NoTypeInformation -Encoding UTF8

            $masterIpFile = Join-Path $OutputDir "FLAGGED_ALL_IPs_$ts.txt"
            ($allFlagged | Select-Object -ExpandProperty ComputerName -Unique) |
                Out-File -FilePath $masterIpFile -Encoding UTF8

            Write-Log ""
            Write-Log "  MASTER FLAGGED FILES:" "WARN"
            Write-Log "    All Targets CSV : $masterFlagFile ($($allFlagged.Count) entries)" "WARN"
            Write-Log "    All IPs         : $masterIpFile" "WARN"

            # Summary table
            Write-Log ""
            Write-Log "  ================================================================" "WARN"
            Write-Log "  FLAGGING SUMMARY" "WARN"
            Write-Log "  ================================================================" "WARN"
            $ruleGroups = $allFlagged | Group-Object FlagPattern
            foreach ($rg in $ruleGroups) {
                $uniqueHosts = ($rg.Group | Select-Object -ExpandProperty ComputerName -Unique).Count
                $rLabel = ($rg.Group | Select-Object -First 1).FlagLabel
                $rRule  = ($rg.Group | Select-Object -First 1).FlagRule
                $labelStr = if ($rLabel) { "  $rLabel" } else { "" }
                Write-Log "  $($rg.Name)  ($rRule)$labelStr" "WARN"
                Write-Log "    -> $($rg.Count) flagged instances across $uniqueHosts hosts" "ERROR"
            }
            Write-Log "  ================================================================" "WARN"
        }
        else {
            Write-Log ""
            Write-Log "  All flag rules passed -- no vulnerable software found!" "SUCCESS"
        }
    }

    # =========================================================================
    #  MASTER CSV -- one row per host, all data combined for triage/sorting
    # =========================================================================
    Write-Log ""
    Write-Log "  Building master host report..."

    # Build lookup: IP -> list of flagged entries
    $flaggedLookup = @{}
    if ($FlagRules -and $FlagRules.Count -gt 0) {
        # $allFlagged was built in the flagging block above
        foreach ($f in $allFlagged) {
            $fip = $f.ComputerName
            if (-not $flaggedLookup.ContainsKey($fip)) {
                $flaggedLookup[$fip] = [System.Collections.Generic.List[PSObject]]::new()
            }
            $flaggedLookup[$fip].Add($f)
        }
    }

    # Build lookup: IP -> list of matching software (use filtered if we have filters)
    $softwareLookup = @{}
    foreach ($sw in @($allSoftware)) {
        $swip = $sw.ComputerName
        if (-not $softwareLookup.ContainsKey($swip)) {
            $softwareLookup[$swip] = [System.Collections.Generic.List[PSObject]]::new()
        }
        $softwareLookup[$swip].Add($sw)
    }

    # Filtered software lookup (for the SoftwareFound column -- show only relevant matches)
    $filteredLookup = @{}
    if ($Filters -and $Filters.Count -gt 0) {
        foreach ($sw in @($filtered)) {
            $swip = $sw.ComputerName
            if (-not $filteredLookup.ContainsKey($swip)) {
                $filteredLookup[$swip] = [System.Collections.Generic.List[PSObject]]::new()
            }
            $filteredLookup[$swip].Add($sw)
        }
    }

    # Build master rows -- start from the full host inventory so every host appears
    $masterRows = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($h in $HostInventory) {
        $ip = $h.IPAddress

        # Determine software scan status
        $isWindows          = ($h.OSType -like "Windows*")
        $scannedForSoftware = $isWindows
        $hostHasSoftware    = $softwareLookup.ContainsKey($ip)
        $hostHasFiltered    = $filteredLookup.ContainsKey($ip)
        $hostFlag           = if ($flaggedLookup.ContainsKey($ip)) { $flaggedLookup[$ip] } else { $null }

        # Build software summary (show filtered matches if filter is active, else total count)
        $swSummary = ""
        if ($Filters -and $Filters.Count -gt 0 -and $hostHasFiltered) {
            $swSummary = ($filteredLookup[$ip] | ForEach-Object {
                $n = $_.Name; $v = $_.Version
                if ($v) { "$n v$v" } else { $n }
            }) -join "; "
        }
        elseif ($hostHasSoftware) {
            $swSummary = "$($softwareLookup[$ip].Count) total software entries"
        }

        # Build flag status
        $flagStatus  = "OK"
        $flagDetails = ""

        if (-not $isWindows) {
            $flagStatus = "NOT SCANNED (non-Windows)"
        }
        elseif (-not $hostHasSoftware) {
            $flagStatus = "SCAN FAILED (no software retrieved)"
        }
        elseif ($Filters -and $Filters.Count -gt 0 -and -not $hostHasFiltered) {
            $flagStatus = "NO MATCHING SOFTWARE"
        }

        # Flagged overrides everything above
        if ($hostFlag -and @($hostFlag).Count -gt 0) {
            $flagStatus  = "*** FLAGGED ***"
            $flagDetails = (@($hostFlag) | ForEach-Object {
                "$($_.SoftwareName) v$($_.Version) ($($_.FlagRule)) $($_.FlagLabel)".Trim()
            }) -join "; "
        }

        $masterRows.Add([PSCustomObject]@{
            IPAddress       = $ip
            Hostname        = $h.Hostname
            OSType          = $h.OSType
            OSVersion       = $h.OSVersion
            Domain          = $h.Domain
            OpenPorts       = $h.OpenPorts
            SoftwareScanned = $scannedForSoftware
            SoftwareFound   = $swSummary
            FlagStatus      = $flagStatus
            FlagDetails     = $flagDetails
        })
    }

    $masterFile = Join-Path $OutputDir "MASTER_HostReport_$ts.csv"
    $masterRows | Sort-Object FlagStatus, IPAddress |
        Export-Csv -Path $masterFile -NoTypeInformation -Encoding UTF8
    Write-Log "  Master host report: $masterFile ($($masterRows.Count) hosts)" "SUCCESS"

    return $filtered
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

# --- Build target list ---
$targetIPs = @()

if ($HostFile) {
    # Direct host list provided -- skip CIDR expansion
    $rawHosts = Get-Content -Path $HostFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' }
    $targetIPs = $rawHosts
    Write-Log "Loaded $($targetIPs.Count) hosts from $HostFile"
}
else {
    # Parse CIDRs
    $cidrList = @()
    if ($CIDRFile -and (Test-Path $CIDRFile)) {
        $cidrList = Get-Content -Path $CIDRFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' }
    }
    elseif ($CIDRs) {
        $cidrList = @($CIDRs -split ',' | ForEach-Object { $_.Trim() })
    }
    else {
        Write-Log "ERROR: Must provide -CIDRs, -CIDRFile, or -HostFile" "ERROR"
        exit 1
    }

    foreach ($cidr in $cidrList) {
        Write-Log "Expanding CIDR: $cidr"
        $expanded = ConvertFrom-CIDR -CIDR $cidr
        Write-Log "  $($expanded.Count) IPs in $cidr"
        $targetIPs += $expanded
    }

    $targetIPs = $targetIPs | Select-Object -Unique
    Write-Log "Total unique IPs to scan: $($targetIPs.Count)"
}

# --- Build software filters ---
$softwareFilters = @()
if ($SoftwareFilterFile -and (Test-Path $SoftwareFilterFile)) {
    $softwareFilters = Get-Content -Path $SoftwareFilterFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' }
    Write-Log "Loaded $($softwareFilters.Count) software filters from $SoftwareFilterFile"
}
elseif ($SoftwareFilter) {
    $softwareFilters = @($SoftwareFilter -split ',' | ForEach-Object { $_.Trim() })
}

# --- Phase 1: Discovery ---
$liveHosts = @()
if ($runDiscovery) {
    $liveHosts = Invoke-HostDiscovery -TargetIPs $targetIPs
}
elseif ($HostFile) {
    # Build synthetic host objects from the host file
    $liveHosts = $targetIPs | ForEach-Object {
        [PSCustomObject]@{
            IPAddress = $_
            Alive     = $true
            Method    = "HostFile"
            OpenPorts = ""
            Hostname  = ""
        }
    }
}
else {
    # Try to load previous discovery output
    $previousDiscovery = Get-ChildItem -Path $OutputDir -Filter "LiveHosts_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($previousDiscovery) {
        Write-Log "Loading previous discovery data: $($previousDiscovery.FullName)"
        $liveHosts = Import-Csv -Path $previousDiscovery.FullName
    }
    else {
        Write-Log "No discovery data available. Run with -Phase Discovery first." "ERROR"
        exit 1
    }
}

# --- Phase 2: Fingerprint ---
$inventory = @()
if ($runFingerprint -and $liveHosts.Count -gt 0) {
    $inventory = Invoke-OSFingerprint -LiveHosts $liveHosts -Credential $Credential
}
elseif ($runSoftware) {
    # Try to load previous fingerprint output
    $previousInventory = Get-ChildItem -Path $OutputDir -Filter "HostInventory_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($previousInventory) {
        Write-Log "Loading previous inventory data: $($previousInventory.FullName)"
        $inventory = Import-Csv -Path $previousInventory.FullName
    }
    elseif ($HostFile) {
        # Assume all hosts are Windows if no fingerprint data
        Write-Log "No fingerprint data -- assuming all hosts are Windows for software scan." "WARN"
        $inventory = $liveHosts | ForEach-Object {
            [PSCustomObject]@{
                IPAddress     = $_.IPAddress
                Hostname      = $_.Hostname
                OSType        = 'Windows (assumed)'
                OSVersion     = ''
                OSBuild       = ''
                Domain        = ''
                DetectMethod  = 'Assumed'
                OpenPorts     = $_.OpenPorts
                Alive         = $true
                LastSeen      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            }
        }
    }
    else {
        Write-Log "No inventory data available. Run with -Phase Fingerprint first." "ERROR"
        exit 1
    }
}

# --- Phase 3: Software Inventory ---
if ($runSoftware -and $inventory.Count -gt 0) {
    $softwareResults = Invoke-SoftwareInventory -HostInventory $inventory -Filters $softwareFilters -FlagRules $flagRules -Credential $Credential
}

# ============================================================================
#  SUMMARY
# ============================================================================
Write-Log ""
Write-Log "========== EXECUTION COMPLETE =========="
Write-Log "  Timestamp  : $ts"
Write-Log "  Output Dir : $(Resolve-Path $OutputDir -ErrorAction SilentlyContinue)"
Write-Log "  Log File   : $logFile"

$outputFiles = Get-ChildItem -Path $OutputDir -Filter "*$ts*" | Select-Object -ExpandProperty Name
foreach ($f in $outputFiles) {
    Write-Log "  Output     : $f"
}

Write-Log "========================================="
