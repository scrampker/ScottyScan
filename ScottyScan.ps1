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
    TCP ports to probe during discovery. Default: all (1-65535).
    Use 'top100' for top 100 enterprise ports, or a comma-separated list.

.PARAMETER FlagFilter
    Comma-separated wildcard patterns for vulnerability flagging.
    Each position corresponds to the same position in -FlagVersion.
    E.g. "*notepad*,*putty*,*flash*"

.PARAMETER FlagVersion
    Comma-separated version thresholds. Text operators: LT, LE, GT, GE, EQ, NE, *.
    E.g. "LT8.9.1,LT0.82,*"

.PARAMETER FlagLabel
    Comma-separated labels for each flag rule.
    E.g. "CVE-2025-15556,CVE-2024-31497,EOL software"

.PARAMETER FlagFilterFile
    Path to a CSV rule file (pattern,versionrule,label per line).

.PARAMETER SoftwareFilterFile
    Path to a text file with one wildcard pattern per line for inventory filtering.

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

.EXAMPLE
    # CLI list scan with software version check and flag rules
    .\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu `
        -Plugins "SoftwareVersionCheck,DHEater-TLS" `
        -FlagFilter "*notepad*,*7-zip*" -FlagVersion "LT8.9.1,LT24.9.0" `
        -FlagLabel "CVE-2025-15556,CVE-2024-11477"

.EXAMPLE
    # Flag rules from a CSV file
    .\ScottyScan.ps1 -List -HostFile .\targets.txt -NoMenu `
        -Plugins "SoftwareVersionCheck" -FlagFilterFile .\flag_rules.csv
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
    [string]$SoftwareFilterFile,
    [string]$FlagFilter,
    [string]$FlagVersion,
    [string]$FlagLabel,
    [string]$FlagFilterFile,
    [string]$PluginDir
)

# ============================================================
#  GLOBALS
# ============================================================
$script:Version      = "1.0.0"
$script:Build        = (Get-Item $PSCommandPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
$script:ConfigFile   = Join-Path $PSScriptRoot "scottyscan.json"
$script:Config       = $null
$script:Validators   = [System.Collections.ArrayList]::new()
$script:LogFile      = $null
$script:Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"

# Top ~100 TCP ports by frequency in enterprise networks.
# Used when port mode is "top100" (quick scan alternative to full 1-65535).
$script:TopPorts = @(
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
    135, 139, 143, 179, 389, 443, 445, 464, 465, 514,
    515, 523, 543, 548, 554, 587, 593, 623, 636, 873,
    902, 993, 995, 1022, 1025, 1080, 1194, 1433, 1434, 1521,
    1723, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3268,
    3269, 3306, 3389, 3690, 4443, 4848, 5000, 5060, 5061, 5222,
    5357, 5432, 5555, 5601, 5672, 5900, 5985, 5986, 6000, 6379,
    6443, 6667, 7001, 7002, 7070, 7443, 8000, 8008, 8009, 8080,
    8081, 8083, 8088, 8090, 8181, 8443, 8444, 8880, 8888, 9000,
    9090, 9091, 9200, 9300, 9443, 9999, 10000, 11211, 27017, 50000
)

function Build-PortList {
    <#
    .SYNOPSIS
        Resolves a port string into an int[] port list, merged with plugin ScanPorts.
        "" or "all" = 1-65535. "top100" = TopPorts. Otherwise CSV of port numbers.
        When SoftwareCheckOnly is set and no explicit port config was given, restricts
        to management ports (135, 445, 5985, 5986) needed for Remote Registry,
        PSRemoting, and WMI -- instead of scanning all 65535.
    #>
    param([string]$PortString, [array]$SelectedPlugins, [switch]$SoftwareCheckOnly)
    $portSet = @{}
    if ($SoftwareCheckOnly -and ([string]::IsNullOrWhiteSpace($PortString) -or $PortString -eq "all")) {
        # Software-only scan: only need management ports for Remote Registry (445),
        # PSRemoting/WinRM (5985, 5986), and WMI/DCOM (135)
        foreach ($p in @(135, 445, 5985, 5986)) { $portSet[$p] = $true }
    } elseif ([string]::IsNullOrWhiteSpace($PortString) -or $PortString -eq "all") {
        1..65535 | ForEach-Object { $portSet[$_] = $true }
    } elseif ($PortString -eq "top100") {
        foreach ($p in $script:TopPorts) { $portSet[$p] = $true }
    } else {
        foreach ($tok in ($PortString -split ',')) {
            $t = $tok.Trim()
            if ($t -match '^\d+$' -and [int]$t -ge 1 -and [int]$t -le 65535) {
                $portSet[[int]$t] = $true
            }
        }
    }
    foreach ($plugin in $SelectedPlugins) {
        if ($plugin.ScanPorts -and $plugin.ScanPorts.Count -gt 0) {
            foreach ($p in $plugin.ScanPorts) { $portSet[[int]$p] = $true }
        }
    }
    # When scanning all ports, put well-known ports first for faster initial results
    if ([string]::IsNullOrWhiteSpace($PortString) -or $PortString -eq "all") {
        $prioritySet = @{}
        foreach ($p in $script:TopPorts) { $prioritySet[$p] = $true }
        foreach ($plugin in $SelectedPlugins) {
            if ($plugin.ScanPorts -and $plugin.ScanPorts.Count -gt 0) {
                foreach ($p in $plugin.ScanPorts) { $prioritySet[[int]$p] = $true }
            }
        }
        $priority = @($prioritySet.Keys | Sort-Object)
        $rest = @($portSet.Keys | Where-Object { -not $prioritySet.ContainsKey($_) } | Sort-Object)
        return @($priority + $rest)
    }
    return @($portSet.Keys | Sort-Object)
}

function Get-PortDisplayString {
    param([string]$PortString, [switch]$SoftwareCheckOnly)
    if ($SoftwareCheckOnly -and ([string]::IsNullOrWhiteSpace($PortString) -or $PortString -eq "all")) {
        return "Management ports only (135, 445, 5985, 5986)"
    } elseif ([string]::IsNullOrWhiteSpace($PortString) -or $PortString -eq "all") {
        return "All ports (1-65535)"
    } elseif ($PortString -eq "top100") {
        return "Top 100 enterprise ports"
    } else {
        $ports = ($PortString -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
        $count = $ports.Count
        if ($count -le 10) {
            return $PortString
        } else {
            return "$count custom ports"
        }
    }
}

$ErrorActionPreference = 'Continue'

# ============================================================
#  DISPLAY HELPERS
# ============================================================

function Write-Banner {
    $banner = @"

  ============================================
   ___          _   _         ___
  / __| __ ___ | |_| |_ _  _/ __| __ __ _ _ _
  \__ \/ _/ _ \|  _|  _| || \__ \/ _/ _' | ' \
  |___/\__\___/\__|\__|\_, /|___/\__\__,_|_||_|
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
    param([string]$Message, [string]$Level = "INFO", [switch]$Silent)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    if (-not $Silent) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "OK"    { "Green" }
            "DEBUG" { "DarkGray" }
            default { "Gray" }
        }
        Write-Host "  $line" -ForegroundColor $color
    }
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
#  INTERACTIVE MENU SYSTEM (TUI with arrow-key navigation)
# ============================================================

function Test-IsConsoleHost {
    <#
    .SYNOPSIS
        Returns $true if running in a real console (supports ReadKey), $false for ISE/etc.
    #>
    return ($host.Name -eq 'ConsoleHost')
}

# ---- Low-level TUI drawing primitives ----
# These write directly to the console buffer at absolute row positions
# using [Console]::SetCursorPosition + [Console]::Write to avoid
# Write-Host's implicit newline which causes terminal scrolling.

function script:Get-ConsoleWidth {
    $w = 80
    try {
        $cw = [Console]::BufferWidth
        if ($cw -gt 0) { $w = $cw }
    } catch {
        try {
            $cw = $host.UI.RawUI.BufferSize.Width
            if ($cw -gt 0) { $w = $cw }
        } catch {}
    }
    return $w
}

function script:Get-ConsoleHeight {
    $h = 25
    try {
        $ch = [Console]::WindowHeight
        if ($ch -gt 0) { $h = $ch }
    } catch {
        try {
            $ch = $host.UI.RawUI.WindowSize.Height
            if ($ch -gt 0) { $h = $ch }
        } catch {}
    }
    return $h
}

function script:Write-LineAt {
    <#
    .SYNOPSIS
        Writes a string at an absolute row, padded to full width, with color.
        Does NOT advance the cursor to a new line -- no scrolling.
    #>
    param(
        [int]$Row,
        [string]$Text,
        [ConsoleColor]$Fg = [ConsoleColor]::Gray,
        [ConsoleColor]$Bg = [ConsoleColor]::Black
    )
    $w = script:Get-ConsoleWidth
    # Truncate if too long, pad if too short. Leave last column empty to
    # prevent the console from wrapping/scrolling on the rightmost cell.
    $maxLen = $w - 1
    if ($Text.Length -gt $maxLen) { $Text = $Text.Substring(0, $maxLen) }
    $padded = $Text.PadRight($maxLen)

    [Console]::SetCursorPosition(0, $Row)
    $oldFg = [Console]::ForegroundColor
    $oldBg = [Console]::BackgroundColor
    [Console]::ForegroundColor = $Fg
    [Console]::BackgroundColor = $Bg
    [Console]::Write($padded)
    [Console]::ForegroundColor = $oldFg
    [Console]::BackgroundColor = $oldBg
}

function script:Clear-Screen {
    <#
    .SYNOPSIS
        Clears the entire visible console window by writing spaces to every row.
    #>
    $h = script:Get-ConsoleHeight
    $w = script:Get-ConsoleWidth
    $blank = " " * ($w - 1)
    $oldFg = [Console]::ForegroundColor
    $oldBg = [Console]::BackgroundColor
    [Console]::ForegroundColor = [ConsoleColor]::Gray
    [Console]::BackgroundColor = [ConsoleColor]::Black
    for ($r = 0; $r -lt $h; $r++) {
        [Console]::SetCursorPosition(0, $r)
        [Console]::Write($blank)
    }
    [Console]::ForegroundColor = $oldFg
    [Console]::BackgroundColor = $oldBg
    [Console]::SetCursorPosition(0, 0)
}

function script:Draw-Banner {
    <#
    .SYNOPSIS
        Draws the ScottyScan banner at the top of the screen (rows 0-7).
        Returns the next available row after the banner.
    #>
    $lines = @(
        ""
        "  ============================================"
        "   ___          _   _         ___"
        "  / __| __ ___ | |_| |_ _  _/ __| __ __ _ _ _"
        "  \__ \/ _/ _ \|  _|  _| || \__ \/ _/ _' | ' \"
        "  |___/\__\___/\__|\__|\_, /|___/\__\__,_|_||_|"
        "                       |__/"
        "  Environment Scanner & Validator  v$($script:Version)"
        "  Build: $($script:Build)"
        "  ============================================"
        ""
    )
    for ($i = 0; $i -lt $lines.Count; $i++) {
        script:Write-LineAt -Row $i -Text $lines[$i] -Fg Cyan
    }
    return $lines.Count
}

# ---- Main TUI Menu Function ----

function Show-InteractiveMenu {
    <#
    .SYNOPSIS
        Full-screen keyboard-navigable TUI menu. Clears and takes over the terminal.
        Returns array of selected Values, or $null if user pressed Escape.
    #>
    param(
        [string]$Title,
        [array]$Items,
        [switch]$SingleSelect,
        [switch]$AllowSelectAll,
        [switch]$IsRootMenu
    )

    # Clone selection state so we don't mutate caller's data
    $selections = [System.Collections.ArrayList]::new()
    foreach ($item in $Items) {
        [void]$selections.Add(@{
            Name        = $item.Name
            Value       = $item.Value
            Selected    = [bool]$item.Selected
            Description = $item.Description
            IsAction    = $false
            Action      = $null
        })
    }

    # For multi-select with AllowSelectAll, prepend ALL / NONE action buttons
    # These are navigable rows that trigger select-all / select-none on Enter or Space
    $actionCount = 0
    if ($AllowSelectAll -and -not $SingleSelect) {
        $selections.Insert(0, @{
            Name = ">> Select NONE"; Value = $null; Selected = $false
            Description = ""; IsAction = $true; Action = "None"
        })
        $selections.Insert(0, @{
            Name = ">> Select ALL";  Value = $null; Selected = $false
            Description = ""; IsAction = $true; Action = "All"
        })
        $actionCount = 2
    }

    # ---- ISE / non-console fallback ----
    if (-not (Test-IsConsoleHost)) {
        # Strip action rows for fallback -- it uses A/N keys instead
        $fallbackSel = [System.Collections.ArrayList]::new()
        foreach ($s in $selections) { if (-not $s.IsAction) { [void]$fallbackSel.Add($s) } }
        return Show-FallbackMenu -Title $Title -Selections $fallbackSel `
                                 -SingleSelect:$SingleSelect -AllowSelectAll:$AllowSelectAll
    }

    # ---- Console TUI ----
    $cursor = 0
    $itemCount = $selections.Count
    if ($itemCount -eq 0) { return @() }

    # Position cursor on the first pre-selected item so users can just hit
    # Enter to keep previous selections. Falls back to first real item (after
    # action buttons) when nothing is pre-selected, or index 0 as last resort.
    $hasPreSelected = $false
    for ($i = 0; $i -lt $itemCount; $i++) {
        if ($selections[$i].Selected -and -not $selections[$i].IsAction) {
            $cursor = $i
            $hasPreSelected = $true
            break
        }
    }
    if (-not $hasPreSelected -and $actionCount -gt 0) {
        $cursor = $actionCount  # first real item, past ALL/NONE buttons
    }

    $scrollOffset = 0
    $prevCursorVisible = $true
    try { $prevCursorVisible = [Console]::CursorVisible } catch {}
    try { [Console]::CursorVisible = $false } catch {}

    try {
        # Full-screen takeover: clear and draw banner
        script:Clear-Screen
        $startRow = script:Draw-Banner

        # Layout rows below the banner:
        #   startRow+0 : title
        #   startRow+1 : hints (normal)
        #   startRow+2 : esc hint (separate so it can be red on root menu)
        #   startRow+3 : blank separator
        #   startRow+4 : scroll-up indicator
        #   startRow+5 .. startRow+5+visibleCount-1 : items
        #   after items : scroll-down indicator

        $titleRow = $startRow
        $hintRow  = $startRow + 1
        $escRow   = $startRow + 2
        $sepRow   = $startRow + 3
        $scrollUpRow = $startRow + 4
        $firstItemRow = $startRow + 5

        # How many item rows fit on screen
        $consoleH = script:Get-ConsoleHeight
        $maxVisible = [Math]::Max(3, $consoleH - $firstItemRow - 2)  # -2 for scroll-down + footer
        $visibleCount = [Math]::Min($itemCount, $maxVisible)

        # Draw static parts (title, hints, separator) once
        script:Write-LineAt -Row $titleRow -Text "  $Title" -Fg Yellow
        if ($SingleSelect) {
            $hintText = "  Up/Down=Move  Enter=Confirm"
        } else {
            $hintText = "  Up/Down=Move  Space=Toggle  Enter=Confirm"
            if ($AllowSelectAll) { $hintText += "  A=All  N=None" }
        }
        script:Write-LineAt -Row $hintRow -Text $hintText -Fg DarkGray
        if ($IsRootMenu) {
            script:Write-LineAt -Row $escRow -Text "  Esc=Exit" -Fg Red
        } else {
            script:Write-LineAt -Row $escRow -Text "  Esc=Back" -Fg DarkGray
        }
        script:Write-LineAt -Row $sepRow -Text ""

        # Track what was last drawn per item row to skip unchanged lines
        $lastDrawn = @{}

        while ($true) {
            # Adjust scroll offset to keep cursor visible
            if ($cursor -lt $scrollOffset) { $scrollOffset = $cursor }
            if ($cursor -ge ($scrollOffset + $visibleCount)) {
                $scrollOffset = $cursor - $visibleCount + 1
            }

            # Scroll-up indicator
            if ($scrollOffset -gt 0) {
                script:Write-LineAt -Row $scrollUpRow -Text "    -- $scrollOffset more above --" -Fg DarkGray
            } else {
                script:Write-LineAt -Row $scrollUpRow -Text ""
            }

            # Draw visible items (only redraw changed lines)
            for ($vi = 0; $vi -lt $visibleCount; $vi++) {
                $idx = $scrollOffset + $vi
                $sel = $selections[$idx]
                $isCursor = ($idx -eq $cursor)
                $row = $firstItemRow + $vi

                if ($sel.IsAction) {
                    # Action button row (ALL / NONE) -- no checkbox marker
                    $lineText = "    $($sel.Name)"
                    if ($isCursor) {
                        $fg = [ConsoleColor]::Black
                        $bg = [ConsoleColor]::DarkCyan
                    } else {
                        $fg = [ConsoleColor]::Cyan
                        $bg = [ConsoleColor]::Black
                    }
                } else {
                    if ($SingleSelect) {
                        $marker = if ($sel.Selected) { "(*)" } else { "( )" }
                    } else {
                        $marker = if ($sel.Selected) { "[X]" } else { "[ ]" }
                    }
                    $descStr = ""
                    if ($sel.Description) { $descStr = " - $($sel.Description)" }
                    $lineText = "    $marker $($sel.Name)$descStr"

                    if ($isCursor) {
                        $fg = [ConsoleColor]::Black
                        $bg = [ConsoleColor]::DarkCyan
                    } elseif ($sel.Selected) {
                        $fg = [ConsoleColor]::Green
                        $bg = [ConsoleColor]::Black
                    } else {
                        $fg = [ConsoleColor]::Gray
                        $bg = [ConsoleColor]::Black
                    }
                }

                # Build a draw-key to detect changes
                $drawKey = "$lineText|$fg|$bg"
                if ($lastDrawn[$vi] -ne $drawKey) {
                    script:Write-LineAt -Row $row -Text $lineText -Fg $fg -Bg $bg
                    $lastDrawn[$vi] = $drawKey
                }
            }

            # Clear any extra rows if visibleCount is less than maxVisible
            for ($vi = $visibleCount; $vi -lt $maxVisible; $vi++) {
                $row = $firstItemRow + $vi
                if ($lastDrawn[$vi]) {
                    script:Write-LineAt -Row $row -Text ""
                    $lastDrawn[$vi] = $null
                }
            }

            # Scroll-down indicator
            $scrollDownRow = $firstItemRow + $visibleCount
            $remaining = $itemCount - ($scrollOffset + $visibleCount)
            if ($remaining -gt 0) {
                script:Write-LineAt -Row $scrollDownRow -Text "    -- $remaining more below --" -Fg DarkGray
            } else {
                script:Write-LineAt -Row $scrollDownRow -Text ""
            }

            # Park cursor off-screen (bottom-left) so it doesn't blink in the menu
            [Console]::SetCursorPosition(0, $consoleH - 1)

            # -- Read key --
            $key = [Console]::ReadKey($true)

            # Check if cursor is on an action button
            $onAction = ($cursor -lt $actionCount -and $selections[$cursor].IsAction)

            switch ($key.Key) {
                'UpArrow' {
                    $cursor--
                    if ($cursor -lt 0) { $cursor = $itemCount - 1 }
                    if ($SingleSelect) {
                        foreach ($s in $selections) { $s.Selected = $false }
                        $selections[$cursor].Selected = $true
                    }
                    $lastDrawn = @{}
                }
                'DownArrow' {
                    $cursor++
                    if ($cursor -ge $itemCount) { $cursor = 0 }
                    if ($SingleSelect) {
                        foreach ($s in $selections) { $s.Selected = $false }
                        $selections[$cursor].Selected = $true
                    }
                    $lastDrawn = @{}
                }
                'Spacebar' {
                    if ($onAction) {
                        # Trigger action button
                        $act = $selections[$cursor].Action
                        if ($act -eq "All")  { foreach ($s in $selections) { if (-not $s.IsAction) { $s.Selected = $true } } }
                        if ($act -eq "None") { foreach ($s in $selections) { if (-not $s.IsAction) { $s.Selected = $false } } }
                    } elseif ($SingleSelect) {
                        foreach ($s in $selections) { $s.Selected = $false }
                        $selections[$cursor].Selected = $true
                    } else {
                        $selections[$cursor].Selected = -not $selections[$cursor].Selected
                    }
                    $lastDrawn = @{}
                }
                'Enter' {
                    if ($onAction) {
                        # Trigger action button then confirm
                        $act = $selections[$cursor].Action
                        if ($act -eq "All")  { foreach ($s in $selections) { if (-not $s.IsAction) { $s.Selected = $true } } }
                        if ($act -eq "None") { foreach ($s in $selections) { if (-not $s.IsAction) { $s.Selected = $false } } }
                    } elseif ($SingleSelect) {
                        foreach ($s in $selections) { $s.Selected = $false }
                        $selections[$cursor].Selected = $true
                    }
                    return @($selections | Where-Object { $_.Selected -and -not $_.IsAction } |
                             ForEach-Object { $_.Value })
                }
                'Escape' {
                    return $null
                }
                default {
                    $ch = [char]::ToUpper($key.KeyChar)
                    if ($ch -eq 'A' -and $AllowSelectAll -and -not $SingleSelect) {
                        foreach ($s in $selections) { if (-not $s.IsAction) { $s.Selected = $true } }
                        $lastDrawn = @{}
                    }
                    elseif ($ch -eq 'N' -and $AllowSelectAll -and -not $SingleSelect) {
                        foreach ($s in $selections) { if (-not $s.IsAction) { $s.Selected = $false } }
                        $lastDrawn = @{}
                    }
                }
            }
        }
    } finally {
        try { [Console]::CursorVisible = $prevCursorVisible } catch {}
    }
}

function Show-FallbackMenu {
    <#
    .SYNOPSIS
        Read-Host based fallback for non-console hosts (ISE, etc.).
        Returns array of selected Values, or $null on empty input with SingleSelect.
    #>
    param(
        [string]$Title,
        [System.Collections.ArrayList]$Selections,
        [switch]$SingleSelect,
        [switch]$AllowSelectAll
    )

    while ($true) {
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Yellow
        if ($SingleSelect) {
            Write-Host "  (Type a number to select, Enter to confirm)" -ForegroundColor DarkGray
        } else {
            Write-Host "  (Toggle: number | A=All | N=None | Enter=Confirm)" -ForegroundColor DarkGray
        }
        Write-Host ""

        for ($i = 0; $i -lt $Selections.Count; $i++) {
            $sel = $Selections[$i]
            if ($SingleSelect) {
                $marker = if ($sel.Selected) { "(*)" } else { "( )" }
            } else {
                $marker = if ($sel.Selected) { "[X]" } else { "[ ]" }
            }
            $descStr = ""
            if ($sel.Description) { $descStr = " - $($sel.Description)" }

            if ($sel.Selected) {
                Write-Host ("    $marker {0}. {1}{2}" -f ($i+1), $sel.Name, $descStr) -ForegroundColor Green
            } else {
                Write-Host ("    $marker {0}. {1}{2}" -f ($i+1), $sel.Name, $descStr) -ForegroundColor Gray
            }
        }

        Write-Host ""
        $response = Read-Host "  Selection"

        if ([string]::IsNullOrWhiteSpace($response)) {
            return @($Selections | Where-Object { $_.Selected } | ForEach-Object { $_.Value })
        }

        $responseUpper = $response.Trim().ToUpper()

        if ($responseUpper -eq 'A' -and $AllowSelectAll -and -not $SingleSelect) {
            foreach ($s in $Selections) { $s.Selected = $true }
            continue
        }
        if ($responseUpper -eq 'N' -and $AllowSelectAll -and -not $SingleSelect) {
            foreach ($s in $Selections) { $s.Selected = $false }
            continue
        }

        $nums = $responseUpper -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
        foreach ($n in $nums) {
            $idx = [int]$n - 1
            if ($idx -ge 0 -and $idx -lt $Selections.Count) {
                if ($SingleSelect) {
                    foreach ($s in $Selections) { $s.Selected = $false }
                    $Selections[$idx].Selected = $true
                } else {
                    $Selections[$idx].Selected = -not $Selections[$idx].Selected
                }
            }
        }
    }
}

function Show-FilePrompt {
    <#
    .SYNOPSIS
        Two-panel TUI input selector. Main panel shows recent history (up to 5),
        Left arrow opens action panel (Browse / Type path). Returns path or $null.
    #>
    param(
        [string]$Title,
        [string[]]$History = @(),
        [string]$Filter = "All files (*.*)|*.*",
        [string]$TypePrompt = "Type the full file path:",
        [switch]$MustExist
    )

    # ---- ISE / non-console fallback ----
    if (-not (Test-IsConsoleHost)) {
        $lastPath = if ($History.Count -gt 0) { $History[0] } else { "" }
        $displayLast = if ($lastPath) { " [last: $lastPath]" } else { "" }
        while ($true) {
            Write-Host ""
            Write-Host "  $Title$displayLast" -ForegroundColor Yellow
            Write-Host "  (Type path, 'browse' for file picker, Enter for last used, empty to go back)" -ForegroundColor DarkGray
            $response = Read-Host "  Path"
            if ([string]::IsNullOrWhiteSpace($response) -and $lastPath) {
                if (-not $MustExist -or (Test-Path $lastPath)) { return $lastPath }
                Write-Host "  File not found: $lastPath" -ForegroundColor Red
                continue
            }
            if ([string]::IsNullOrWhiteSpace($response)) { return $null }
            if ($response.Trim().ToLower() -eq 'browse') {
                $picked = Show-FilePicker -Filter $Filter -LastFolder (Split-Path $lastPath -Parent -ErrorAction SilentlyContinue)
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

    # ---- Console TUI ----
    $panel = "files"       # "files" or "actions"
    $fileCursor = 0
    $actionCursor = 0
    $actions = @("Browse for file...", "Type manually...")
    $errorMsg = ""

    # If no history, start on actions panel
    if ($History.Count -eq 0) { $panel = "actions" }

    $prevCursorVisible = $true
    try { $prevCursorVisible = [Console]::CursorVisible } catch {}
    try { [Console]::CursorVisible = $false } catch {}

    try {
        script:Clear-Screen
        $startRow = script:Draw-Banner
        $consoleH = script:Get-ConsoleHeight
        $lastDrawn = @{}

        while ($true) {
            $r = $startRow

            # Title
            script:Write-LineAt -Row $r -Text "  $Title" -Fg Yellow; $r++
            script:Write-LineAt -Row $r -Text ""; $r++

            if ($panel -eq "files") {
                # ---- File history panel ----
                if ($History.Count -eq 0) {
                    $drawKey = "empty"
                    if ($lastDrawn[$r] -ne $drawKey) {
                        script:Write-LineAt -Row $r -Text "    (no recent entries)" -Fg DarkGray
                        $lastDrawn[$r] = $drawKey
                    }
                    $r++
                } else {
                    $w = script:Get-ConsoleWidth
                    for ($i = 0; $i -lt $History.Count; $i++) {
                        $isCursor = ($i -eq $fileCursor)
                        $prefix = if ($isCursor) { "  > " } else { "    " }
                        $path = $History[$i]
                        $maxPathLen = $w - 8
                        if ($path.Length -gt $maxPathLen) {
                            $path = "..." + $path.Substring($path.Length - $maxPathLen + 3)
                        }
                        $lineText = "$prefix$path"
                        if ($isCursor) {
                            $fg = [ConsoleColor]::Black; $bg = [ConsoleColor]::DarkCyan
                        } else {
                            $fg = [ConsoleColor]::Gray; $bg = [ConsoleColor]::Black
                        }
                        $drawKey = "$lineText|$fg|$bg"
                        if ($lastDrawn[$r] -ne $drawKey) {
                            script:Write-LineAt -Row $r -Text $lineText -Fg $fg -Bg $bg
                            $lastDrawn[$r] = $drawKey
                        }
                        $r++
                    }
                }

                # Error message row
                $r++
                $errKey = "err:$errorMsg"
                if ($lastDrawn[$r] -ne $errKey) {
                    if ($errorMsg) {
                        script:Write-LineAt -Row $r -Text "  $errorMsg" -Fg Red
                    } else {
                        script:Write-LineAt -Row $r -Text ""
                    }
                    $lastDrawn[$r] = $errKey
                }
                $r++

                # Hint lines
                $hintText = "  Up/Down=Navigate  Enter=Select  Left=More options  Esc=Back"
                $hintKey = "hint:$hintText"
                if ($lastDrawn[$r] -ne $hintKey) {
                    script:Write-LineAt -Row $r -Text $hintText -Fg DarkGray
                    $lastDrawn[$r] = $hintKey
                }

            } else {
                # ---- Action panel ----
                for ($i = 0; $i -lt $actions.Count; $i++) {
                    $isCursor = ($i -eq $actionCursor)
                    $prefix = if ($isCursor) { "  > " } else { "    " }
                    $lineText = "$prefix>> $($actions[$i])"
                    if ($isCursor) {
                        $fg = [ConsoleColor]::Black; $bg = [ConsoleColor]::DarkCyan
                    } else {
                        $fg = [ConsoleColor]::Cyan; $bg = [ConsoleColor]::Black
                    }
                    $drawKey = "$lineText|$fg|$bg"
                    if ($lastDrawn[$r] -ne $drawKey) {
                        script:Write-LineAt -Row $r -Text $lineText -Fg $fg -Bg $bg
                        $lastDrawn[$r] = $drawKey
                    }
                    $r++
                }

                # Error message row
                $r++
                $errKey = "err:$errorMsg"
                if ($lastDrawn[$r] -ne $errKey) {
                    if ($errorMsg) {
                        script:Write-LineAt -Row $r -Text "  $errorMsg" -Fg Red
                    } else {
                        script:Write-LineAt -Row $r -Text ""
                    }
                    $lastDrawn[$r] = $errKey
                }
                $r++

                # Hint lines
                $backText = if ($History.Count -gt 0) { "Right=Back to list  " } else { "" }
                $hintText = "  Up/Down=Navigate  Enter=Select  ${backText}Esc=Back"
                $hintKey = "hint:$hintText"
                if ($lastDrawn[$r] -ne $hintKey) {
                    script:Write-LineAt -Row $r -Text $hintText -Fg DarkGray
                    $lastDrawn[$r] = $hintKey
                }
            }

            # Clear remaining rows below current content
            $clearStart = $r + 1
            for ($cr = $clearStart; $cr -lt $consoleH - 1; $cr++) {
                if ($lastDrawn[$cr]) {
                    script:Write-LineAt -Row $cr -Text ""
                    $lastDrawn[$cr] = $null
                }
            }

            # Park cursor
            [Console]::SetCursorPosition(0, $consoleH - 1)
            $errorMsg = ""

            # ---- Read key ----
            $key = [Console]::ReadKey($true)

            switch ($key.Key) {
                'UpArrow' {
                    if ($panel -eq "files" -and $History.Count -gt 0) {
                        $fileCursor = ($fileCursor - 1 + $History.Count) % $History.Count
                    } elseif ($panel -eq "actions") {
                        $actionCursor = ($actionCursor - 1 + $actions.Count) % $actions.Count
                    }
                    $lastDrawn = @{}
                }
                'DownArrow' {
                    if ($panel -eq "files" -and $History.Count -gt 0) {
                        $fileCursor = ($fileCursor + 1) % $History.Count
                    } elseif ($panel -eq "actions") {
                        $actionCursor = ($actionCursor + 1) % $actions.Count
                    }
                    $lastDrawn = @{}
                }
                'LeftArrow' {
                    if ($panel -eq "files") {
                        $panel = "actions"
                        $actionCursor = 0
                        $lastDrawn = @{}
                    }
                }
                'RightArrow' {
                    if ($panel -eq "actions" -and $History.Count -gt 0) {
                        $panel = "files"
                        $lastDrawn = @{}
                    }
                }
                'Enter' {
                    if ($panel -eq "files" -and $History.Count -gt 0) {
                        $selected = $History[$fileCursor]
                        if ($MustExist -and -not (Test-Path $selected)) {
                            $errorMsg = "File not found: $selected"
                        } else {
                            return $selected
                        }
                    } elseif ($panel -eq "actions") {
                        switch ($actionCursor) {
                            0 {
                                # Browse for file
                                try { [Console]::CursorVisible = $true } catch {}
                                $lastFolder = if ($History.Count -gt 0) {
                                    Split-Path $History[0] -Parent -ErrorAction SilentlyContinue
                                } else { $null }
                                $picked = Show-FilePicker -Filter $Filter -LastFolder $lastFolder
                                try { [Console]::CursorVisible = $false } catch {}
                                if ($picked) {
                                    if ($MustExist -and -not (Test-Path $picked)) {
                                        $errorMsg = "File not found: $picked"
                                    } else {
                                        return $picked
                                    }
                                } else {
                                    $errorMsg = "No file selected."
                                }
                                # Force full redraw after dialog
                                script:Clear-Screen
                                $startRow = script:Draw-Banner
                                $lastDrawn = @{}
                            }
                            1 {
                                # Type path manually
                                script:Clear-Screen
                                $startRow2 = script:Draw-Banner
                                script:Write-LineAt -Row $startRow2 -Text "  $TypePrompt" -Fg Yellow
                                script:Write-LineAt -Row ($startRow2 + 1) -Text "  (empty to go back)" -Fg DarkGray
                                [Console]::SetCursorPosition(0, $startRow2 + 3)
                                try { [Console]::CursorVisible = $true } catch {}
                                $typed = Read-Host "  Path"
                                try { [Console]::CursorVisible = $false } catch {}
                                if (-not [string]::IsNullOrWhiteSpace($typed)) {
                                    $resolved = $typed.Trim().Trim('"').Trim("'")
                                    if ($MustExist -and -not (Test-Path $resolved)) {
                                        $errorMsg = "File not found: $resolved"
                                    } else {
                                        return $resolved
                                    }
                                }
                                # Force full redraw
                                script:Clear-Screen
                                $startRow = script:Draw-Banner
                                $lastDrawn = @{}
                            }
                        }
                    }
                }
                'Escape' {
                    return $null
                }
            }
        }
    } finally {
        try { [Console]::CursorVisible = $prevCursorVisible } catch {}
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
        if (Test-IsConsoleHost) {
            # Will be shown by caller
        } else {
            Write-Host "  (GUI file picker unavailable in this session)" -ForegroundColor DarkGray
        }
    }
    return $null
}

function Show-TextPrompt {
    <#
    .SYNOPSIS
        Full-screen text prompt. Draws on the TUI layout.
    #>
    param(
        [string]$Prompt,
        [string]$Default,
        [string]$LastValue
    )

    $isConsole = Test-IsConsoleHost

    $displayDefault = ""
    if ($LastValue) {
        $displayDefault = " [last: $LastValue]"
    } elseif ($Default) {
        $displayDefault = " [default: $Default]"
    }

    if ($isConsole) {
        script:Clear-Screen
        $startRow = script:Draw-Banner
        script:Write-LineAt -Row $startRow -Text "  $Prompt$displayDefault" -Fg Yellow
        script:Write-LineAt -Row ($startRow + 1) -Text ""
        [Console]::SetCursorPosition(0, $startRow + 2)
        try { [Console]::CursorVisible = $true } catch {}
    } else {
        Write-Host ""
        Write-Host "  $Prompt$displayDefault" -ForegroundColor Yellow
    }

    $response = Read-Host "  Value"
    if ([string]::IsNullOrWhiteSpace($response)) {
        if ($LastValue) { return $LastValue }
        return $Default
    }
    return $response.Trim()
}

function Show-SettingsMenu {
    <#
    .SYNOPSIS
        Interactive settings for threads, timeout, and ports.
        Returns hashtable @{ Threads; Timeout; Ports } or $null on Escape.
    #>
    param(
        [int]$CurrentThreads,
        [int]$CurrentTimeout,
        [string]$CurrentPorts
    )

    $portsDisplay = Get-PortDisplayString $CurrentPorts

    $settingsItems = @(
        @{ Name = "Max threads: $CurrentThreads";    Value = "Threads"; Selected = $false; Description = "Parallel scan threads" }
        @{ Name = "Timeout (ms): $CurrentTimeout";   Value = "Timeout"; Selected = $false; Description = "Per-test network timeout" }
        @{ Name = "Discovery ports: $portsDisplay";   Value = "Ports";   Selected = $false; Description = "TCP ports for host discovery" }
        @{ Name = ">> Continue with current settings"; Value = "Done";   Selected = $true;  Description = "" }
    )

    while ($true) {
        $portsDisplay = Get-PortDisplayString $CurrentPorts
        $settingsItems[0].Name = "Max threads: $CurrentThreads"
        $settingsItems[1].Name = "Timeout (ms): $CurrentTimeout"
        $settingsItems[2].Name = "Discovery ports: $portsDisplay"

        $choice = Show-InteractiveMenu -Title "Settings (select to change, or continue):" `
                                       -Items $settingsItems -SingleSelect

        if ($null -eq $choice) { return $null }

        $picked = $choice | Select-Object -First 1

        switch ($picked) {
            "Threads" {
                $val = Show-TextPrompt -Prompt "Max parallel threads:" -Default "$CurrentThreads"
                if ($val -match '^\d+$' -and [int]$val -gt 0) { $CurrentThreads = [int]$val }
            }
            "Timeout" {
                $val = Show-TextPrompt -Prompt "Timeout per test (ms):" -Default "$CurrentTimeout"
                if ($val -match '^\d+$' -and [int]$val -gt 0) { $CurrentTimeout = [int]$val }
            }
            "Ports" {
                $portOptions = @(
                    @{ Name = "All ports (1-65535)";      Value = "all";    Selected = ([string]::IsNullOrWhiteSpace($CurrentPorts) -or $CurrentPorts -eq "all"); Description = "Full TCP port scan" }
                    @{ Name = "Top 100 enterprise ports"; Value = "top100"; Selected = ($CurrentPorts -eq "top100"); Description = "Common enterprise services" }
                    @{ Name = "Custom port list";         Value = "custom"; Selected = ($CurrentPorts -ne "" -and $CurrentPorts -ne "all" -and $CurrentPorts -ne "top100"); Description = "Specify individual ports" }
                )
                $portChoice = Show-InteractiveMenu -Title "Discovery port range:" -Items $portOptions -SingleSelect
                if ($null -ne $portChoice) {
                    $portPicked = $portChoice | Select-Object -First 1
                    switch ($portPicked) {
                        "all"    { $CurrentPorts = "" }
                        "top100" { $CurrentPorts = "top100" }
                        "custom" {
                            $existing = if ($CurrentPorts -and $CurrentPorts -ne "all" -and $CurrentPorts -ne "top100") { $CurrentPorts } else { "22,80,443,3389" }
                            $val = Show-TextPrompt -Prompt "TCP ports (comma-separated):" -Default $existing
                            if ($val) { $CurrentPorts = $val }
                        }
                    }
                }
            }
            "Done" {
                return @{
                    Threads = $CurrentThreads
                    Timeout = $CurrentTimeout
                    Ports   = $CurrentPorts
                }
            }
        }
    }
}

function Show-ConfirmationScreen {
    <#
    .SYNOPSIS
        Full-screen summary of all selections. Returns $true on Enter, $false on Escape.
    #>
    param(
        [string]$Mode,
        [string[]]$PluginNames,
        [string[]]$OutputNames,
        [int]$Threads,
        [int]$Timeout,
        [string]$Ports,
        [string]$InputDetail,
        [string]$SoftwareCheckDetail,
        [switch]$SoftwareCheckOnly,
        [string]$CredentialDisplay
    )

    $portsDisplay = Get-PortDisplayString $Ports -SoftwareCheckOnly:$SoftwareCheckOnly

    if (-not (Test-IsConsoleHost)) {
        Write-Host ""
        Write-Host "  ==========================================" -ForegroundColor Yellow
        Write-Host "  READY TO EXECUTE" -ForegroundColor Yellow
        Write-Host "  ==========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Mode:      $Mode" -ForegroundColor White
        Write-Host "  Plugins:   $($PluginNames -join ', ')" -ForegroundColor White
        if ($SoftwareCheckDetail) {
            Write-Host "  SW Check:  $SoftwareCheckDetail" -ForegroundColor White
        }
        if ($CredentialDisplay) {
            Write-Host "  Creds:     $CredentialDisplay" -ForegroundColor White
        }
        Write-Host "  Outputs:   $($OutputNames -join ', ')" -ForegroundColor White
        Write-Host "  Threads:   $Threads" -ForegroundColor White
        Write-Host "  Timeout:   ${Timeout}ms" -ForegroundColor White
        Write-Host "  Ports:     $portsDisplay" -ForegroundColor White
        Write-Host "  Input:     $InputDetail" -ForegroundColor White
        Write-Host ""
        $response = Read-Host "  Press Enter to execute, or type 'back' to go back"
        return ($response.Trim().ToLower() -ne 'back')
    }

    $prevCursorVisible = $true
    try { $prevCursorVisible = [Console]::CursorVisible } catch {}
    try { [Console]::CursorVisible = $false } catch {}

    try {
        script:Clear-Screen
        $startRow = script:Draw-Banner

        $r = $startRow
        script:Write-LineAt -Row $r -Text "  ==========================================" -Fg Yellow; $r++
        script:Write-LineAt -Row $r -Text "  READY TO EXECUTE" -Fg Yellow; $r++
        script:Write-LineAt -Row $r -Text "  ==========================================" -Fg Yellow; $r++
        script:Write-LineAt -Row $r -Text ""; $r++
        script:Write-LineAt -Row $r -Text "  Mode:      $Mode" -Fg White; $r++
        script:Write-LineAt -Row $r -Text "  Plugins:   $($PluginNames -join ', ')" -Fg White; $r++
        if ($SoftwareCheckDetail) {
            script:Write-LineAt -Row $r -Text "  SW Check:  $SoftwareCheckDetail" -Fg White; $r++
        }
        if ($CredentialDisplay) {
            script:Write-LineAt -Row $r -Text "  Creds:     $CredentialDisplay" -Fg White; $r++
        }
        script:Write-LineAt -Row $r -Text "  Outputs:   $($OutputNames -join ', ')" -Fg White; $r++
        script:Write-LineAt -Row $r -Text "  Threads:   $Threads" -Fg White; $r++
        script:Write-LineAt -Row $r -Text "  Timeout:   ${Timeout}ms" -Fg White; $r++
        script:Write-LineAt -Row $r -Text "  Ports:     $portsDisplay" -Fg White; $r++
        script:Write-LineAt -Row $r -Text "  Input:     $InputDetail" -Fg White; $r++
        script:Write-LineAt -Row $r -Text ""; $r++
        script:Write-LineAt -Row $r -Text "  Enter=Execute  Esc=Back" -Fg DarkGray; $r++

        $consoleH = script:Get-ConsoleHeight
        [Console]::SetCursorPosition(0, $consoleH - 1)

        while ($true) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'Enter') { return $true }
            if ($key.Key -eq 'Escape') { return $false }
        }
    } finally {
        try { [Console]::CursorVisible = $prevCursorVisible } catch {}
    }
}

function Get-ModeInput {
    <#
    .SYNOPSIS
        Gathers mode-specific input (CIDRs, host file, or CSV path).
        Uses two-panel TUI with history. Returns hashtable or $null on Escape.
    #>
    param(
        [string]$Mode,
        [PSCustomObject]$Config
    )

    switch ($Mode) {
        "Scan" {
            $history = Get-InputHistory -HistoryKey "CIDRInputHistory" -LegacyKey "LastCIDRs"
            # Also check LastCIDRFile as legacy fallback
            if ($history.Count -eq 0 -and $Config.PSObject.Properties.Name -contains 'LastCIDRFile' -and $Config.LastCIDRFile) {
                $history = @($Config.LastCIDRFile)
            }
            $cidrResponse = Show-FilePrompt -Title "Enter CIDRs or select a CIDR file:" `
                                            -History $history `
                                            -Filter "Text files (*.txt)|*.txt|All files (*.*)|*.*" `
                                            -TypePrompt "Type CIDRs (comma-separated) or a file path:"
            if ([string]::IsNullOrWhiteSpace($cidrResponse)) { return $null }

            $cidrList = @()
            if (Test-Path $cidrResponse -ErrorAction SilentlyContinue) {
                $cidrList = Get-Content $cidrResponse | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
                return @{ CIDRList = $cidrList; CIDRFile = $cidrResponse; CIDRs = ""; RawInput = $cidrResponse }
            } else {
                $cidrList = $cidrResponse -split ',' | ForEach-Object { $_.Trim() }
                return @{ CIDRList = $cidrList; CIDRFile = ""; CIDRs = ($cidrList -join ', '); RawInput = $cidrResponse }
            }
        }
        "List" {
            $history = Get-InputHistory -HistoryKey "HostFileHistory" -LegacyKey "LastHostFile"
            $hostFile = Show-FilePrompt -Title "Host list file (one IP/hostname per line):" `
                                        -History $history `
                                        -Filter "Text files (*.txt)|*.txt|All files (*.*)|*.*" `
                                        -TypePrompt "Type the full file path:" `
                                        -MustExist
            if (-not $hostFile) { return $null }
            return @{ HostFile = $hostFile }
        }
        "Validate" {
            $history = Get-InputHistory -HistoryKey "InputCSVHistory" -LegacyKey "LastInputCSV"
            $csvPath = Show-FilePrompt -Title "OpenVAS CSV file:" `
                                       -History $history `
                                       -Filter "CSV files (*.csv)|*.csv|All files (*.*)|*.*" `
                                       -TypePrompt "Type the full CSV file path:" `
                                       -MustExist
            if (-not $csvPath) { return $null }
            return @{ CSVPath = $csvPath }
        }
    }
    return $null
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
        CIDRInputHistory    = @()
        HostFileHistory     = @()
        InputCSVHistory     = @()
        FlagRuleFileHistory = @()
        DefaultThreads   = 20
        DefaultTimeoutMs = 5000
        DefaultPlugins   = @()
        DefaultOutputs   = @("MasterCSV", "SummaryReport", "PerPluginCSV", "DiscoveryCSV")
        DefaultPorts     = ""
        LastOutputDir    = ".\output_reports"
        SavedFlagRules   = @()
        LastSoftwareFilter = ""
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

function Push-InputHistory {
    <#
    .SYNOPSIS
        Pushes a value to the front of a config history array (max 5, deduped).
    #>
    param([string]$ConfigKey, [string]$Value)
    $history = @()
    if ($script:Config.PSObject.Properties.Name -contains $ConfigKey) {
        $history = @($script:Config.$ConfigKey | Where-Object { $_ })
    }
    $history = @($history | Where-Object { $_ -ne $Value })
    $history = @($Value) + $history
    if ($history.Count -gt 5) { $history = $history[0..4] }
    Update-ConfigValue $ConfigKey $history
}

function Get-InputHistory {
    <#
    .SYNOPSIS
        Returns history array from config, migrating from legacy Last* fields if needed.
    #>
    param([string]$HistoryKey, [string]$LegacyKey)
    $history = @()
    if ($script:Config.PSObject.Properties.Name -contains $HistoryKey) {
        $history = @($script:Config.$HistoryKey | Where-Object { $_ })
    }
    # Migrate from legacy Last* field if history is empty
    if ($history.Count -eq 0 -and $LegacyKey) {
        if ($script:Config.PSObject.Properties.Name -contains $LegacyKey) {
            $legacy = $script:Config.$LegacyKey
            if ($legacy) { $history = @($legacy) }
        }
    }
    return $history
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
#  VERSION COMPARISON ENGINE
# ============================================================

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

function Import-FlagRules {
    <#
    .SYNOPSIS
        Builds an array of flag rule objects from CLI parameters and/or a rule file.
        Each rule: @{ Pattern = "*notepad*"; VersionRule = "LT8.9.1"; Label = "CVE-..." }
    #>
    param(
        [string]$FlagFilter,
        [string]$FlagVersion,
        [string]$FlagLabel,
        [string]$FlagFilterFile
    )

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

    return $flagRules
}

# Stringified version helpers for RunspacePool injection
$script:VersionHelperString = @'
function Compare-VersionStrings {
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
    param([string]$Version, [string]$Rule)
    $Rule = $Rule.Trim()
    if ($Rule -eq '*') { return $true }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $true }
    $operator = ''
    $threshold = ''
    if ($Rule -match '^(LE|GE|NE|LT|GT|EQ)(.+)$') {
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
        $operator  = $Matches[1]
        $threshold = $Matches[2].Trim()
    }
    else {
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
'@

# ============================================================
#  SOFTWARE ENUMERATION FUNCTIONS
# ============================================================

function Get-SoftwareFromRegistry {
    <# Remote Registry method -- both Uninstall + WOW6432Node #>
    param([string]$ComputerName)

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
                        Architecture   = if ($key -like "*WOW6432*") { "x86" } else { "x64" }
                        Source         = "Registry"
                    })
                }
                catch { }
            }
            $reg.Close()
        }
        catch { }
    }
    return $results
}

function Get-SoftwareFromPSRemoting {
    <# PSRemoting fallback -- reads registry locally via Invoke-Command #>
    param([string]$ComputerName, [PSCredential]$Credential)

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
                Architecture   = $r.Architecture
                Source         = "PSRemoting"
            })
        }
    }
    catch { }
    return $results
}

function Get-SoftwareFromWMI {
    <# WMI/CIM fallback -- Win32_Product (slow, last resort) #>
    param([string]$ComputerName, [PSCredential]$Credential)

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
                Architecture   = ""
                Source         = "WMI"
            })
        }
    }
    catch { }
    return $results
}

# Stringified software enumeration for RunspacePool injection
$script:SoftwareHelperString = @'
function Get-SoftwareFromRegistry {
    param([string]$ComputerName)
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
                        Architecture   = if ($key -like "*WOW6432*") { "x86" } else { "x64" }
                        Source         = "Registry"
                    })
                }
                catch { }
            }
            $reg.Close()
        }
        catch { }
    }
    return $results
}

function Get-SoftwareFromPSRemoting {
    param([string]$ComputerName, [PSCredential]$Credential)
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
                Architecture   = $r.Architecture
                Source         = "PSRemoting"
            })
        }
    }
    catch { }
    return $results
}

function Get-SoftwareFromWMI {
    param([string]$ComputerName, [PSCredential]$Credential)
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
                Architecture   = ""
                Source         = "WMI"
            })
        }
    }
    catch { }
    return $results
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
    $progressState = [hashtable]::Synchronized(@{})

    foreach ($ip in $IPList) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($IP, $Ports, $Timeout, $Progress)
            $result = @{
                IP        = $IP
                Alive     = $false
                OpenPorts = @()
                Hostname  = ""
                OS        = ""
                TTL       = 0
            }
            # Ping (500ms is plenty for LAN/WAN; $Timeout is for plugin tests)
            $pingTimeout = 500
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $reply = $ping.Send($IP, $pingTimeout)
                if ($reply.Status -eq 'Success') {
                    $result.Alive = $true
                    $result.TTL = $reply.Options.Ttl
                }
                $ping.Dispose()
            } catch {}

            # Port scan - batched async for efficiency with large port lists
            $batchSize = 2000
            $connectTimeout = 500
            $openList = [System.Collections.ArrayList]::new()
            $totalPorts = $Ports.Count
            for ($i = 0; $i -lt $totalPorts; $i += $batchSize) {
                $endIdx = [Math]::Min($i + $batchSize - 1, $totalPorts - 1)
                $batch = @($Ports[$i..$endIdx])
                $conns = [System.Collections.ArrayList]::new()
                foreach ($port in $batch) {
                    try {
                        $c = New-Object System.Net.Sockets.TcpClient
                        $ar = $c.BeginConnect($IP, $port, $null, $null)
                        [void]$conns.Add(@{ C = $c; A = $ar; P = $port })
                    } catch {}
                }
                [System.Threading.Thread]::Sleep($connectTimeout)
                foreach ($conn in $conns) {
                    try {
                        if ($conn.A.IsCompleted) {
                            try {
                                $conn.C.EndConnect($conn.A)
                                [void]$openList.Add($conn.P)
                                $result.Alive = $true
                            } catch {}
                        }
                        $conn.C.Close()
                    } catch { try { $conn.C.Close() } catch {} }
                }
                # Report progress after batch: port range + open ports found so far
                if ($Progress) {
                    $Progress[$IP] = @{
                        StartPort = $Ports[$i]
                        EndPort   = $Ports[$endIdx]
                        Scanned   = $endIdx + 1
                        Total     = $totalPorts
                        OpenPorts = @($openList)
                    }
                }
            }
            $result.OpenPorts = @($openList)
            # Mark this IP as done in progress
            if ($Progress) { $Progress.Remove($IP) }

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
        }).AddArgument($ip).AddArgument($PortList).AddArgument($TimeoutMs).AddArgument($progressState)

        $handle = $ps.BeginInvoke()
        [void]$jobs.Add(@{ PowerShell = $ps; Handle = $handle; IP = $ip })
    }

    # Collect results via polling with fixed-position scrollable display
    $liveHosts = [System.Collections.ArrayList]::new()
    $completed = 0
    $total = $jobs.Count
    $pending = [System.Collections.ArrayList]::new($jobs)
    $spinChars = @('|', '/', '-', '\')
    $spinIdx = 0
    $startTime = [DateTime]::Now
    $displayedPorts = @{}          # Track which ports we've counted per IP
    $totalPortsFound = 0
    $hostResultBuf = [System.Collections.ArrayList]::new()   # host result lines + colors
    $portBuf = [System.Collections.ArrayList]::new()         # port discovery lines

    # Display layout: hostWindow (6) + portHeader (1) + portWindow (6) + spinner (1) + hint (1) = 15 rows
    $hostWinSize = 6
    $portWinSize = 6
    $displayRows = $hostWinSize + 1 + $portWinSize + 1 + 1  # 15

    Write-Host "  Scanning $($PortList.Count) ports across $total hosts..." -ForegroundColor Gray

    # Reserve vertical space and anchor
    for ($ln = 0; $ln -lt $displayRows; $ln++) { Write-Host "" }
    $anchorY = [Console]::CursorTop - $displayRows

    [Console]::CursorVisible = $false
    try {
    while ($pending.Count -gt 0) {
        # --- Check completed jobs ---
        for ($i = $pending.Count - 1; $i -ge 0; $i--) {
            $job = $pending[$i]
            if ($job.Handle.IsCompleted) {
                try {
                    $r = $job.PowerShell.EndInvoke($job.Handle)
                    if ($r -and $r.Count -gt 0) {
                        $hostResult = $r[0]
                        $completed++
                        if ($hostResult.Alive) {
                            [void]$liveHosts.Add($hostResult)
                            $portCount = @($hostResult.OpenPorts).Count
                            $osStr = if ($hostResult.OS) { $hostResult.OS } else { "Unknown" }
                            $hostStr = if ($hostResult.Hostname) { $hostResult.Hostname } else { "" }
                            $line = "  [{0}/{1}] [+] {2,-15} ALIVE  {3} open port(s)  {4}  {5}" -f `
                                $completed, $total, $hostResult.IP, $portCount, $osStr, $hostStr
                            [void]$hostResultBuf.Add(@{ Text = $line; Color = [ConsoleColor]::Green })
                            # Update port counter from final results (progress polling
                            # may have missed them on fast scans with few ports)
                            if (-not $displayedPorts.ContainsKey($hostResult.IP)) { $displayedPorts[$hostResult.IP] = @{} }
                            foreach ($op in $hostResult.OpenPorts) {
                                if (-not $displayedPorts[$hostResult.IP].ContainsKey($op)) {
                                    $displayedPorts[$hostResult.IP][$op] = $true
                                    $totalPortsFound++
                                    [void]$portBuf.Add("  [*] $($hostResult.IP):${op}")
                                }
                            }
                            $portsJoined = ($hostResult.OpenPorts | Sort-Object) -join ','
                            Write-Log "ALIVE $($hostResult.IP) ($hostStr) -- OS=$osStr TTL=$($hostResult.TTL) Ports=[$portsJoined]" -Silent
                        } else {
                            $line = "  [{0}/{1}] [-] {2,-15} no response" -f $completed, $total, $hostResult.IP
                            [void]$hostResultBuf.Add(@{ Text = $line; Color = [ConsoleColor]::DarkGray })
                            Write-Log "DEAD $($hostResult.IP)" "DEBUG" -Silent
                        }
                    } else {
                        $completed++
                    }
                } catch {
                    $completed++
                }
                $job.PowerShell.Dispose()
                $pending.RemoveAt($i)
            }
        }

        # --- Check for newly discovered open ports ---
        $portInfo = ""
        try {
            $snapKeys = @($progressState.Keys)
            foreach ($sKey in $snapKeys) {
                $entry = $progressState[$sKey]
                if ($entry -and $entry.OpenPorts -and $entry.OpenPorts.Count -gt 0) {
                    if (-not $displayedPorts.ContainsKey($sKey)) { $displayedPorts[$sKey] = @{} }
                    foreach ($op in $entry.OpenPorts) {
                        if (-not $displayedPorts[$sKey].ContainsKey($op)) {
                            $displayedPorts[$sKey][$op] = $true
                            $totalPortsFound++
                            [void]$portBuf.Add("  [*] ${sKey}:${op}")
                        }
                    }
                }
            }
            # Port range info from first active host
            if ($snapKeys.Count -gt 0) {
                $sample = $progressState[$snapKeys[0]]
                if ($sample) {
                    $pct = [Math]::Round(($sample.Scanned / $sample.Total) * 100)
                    $portInfo = " -- ports $($sample.StartPort)-$($sample.EndPort) ($pct%)"
                }
            }
        } catch {}

        # --- Redraw the fixed display block ---
        $row = $anchorY

        # Host results window (last N entries)
        $hStart = [Math]::Max(0, $hostResultBuf.Count - $hostWinSize)
        for ($h = 0; $h -lt $hostWinSize; $h++) {
            $idx = $hStart + $h
            if ($idx -lt $hostResultBuf.Count) {
                $entry = $hostResultBuf[$idx]
                script:Write-LineAt -Row $row -Text $entry.Text -Fg $entry.Color
            } else {
                script:Write-LineAt -Row $row -Text ""
            }
            $row++
        }

        # Port window header with total counter
        $portHeader = "  -- Open ports ($totalPortsFound found) --"
        script:Write-LineAt -Row $row -Text $portHeader -Fg ([ConsoleColor]::DarkCyan)
        $row++

        # Port discoveries window (last N entries)
        $pStart = [Math]::Max(0, $portBuf.Count - $portWinSize)
        for ($p = 0; $p -lt $portWinSize; $p++) {
            $idx = $pStart + $p
            if ($idx -lt $portBuf.Count) {
                script:Write-LineAt -Row $row -Text $portBuf[$idx] -Fg ([ConsoleColor]::Cyan)
            } else {
                script:Write-LineAt -Row $row -Text ""
            }
            $row++
        }

        # Spinner / status line
        $elapsed = ([DateTime]::Now - $startTime).ToString("mm\:ss")
        $spin = $spinChars[$spinIdx % $spinChars.Count]
        $spinIdx++
        if ($pending.Count -gt 0) {
            $statusLine = "  $spin  [{0}/{1} hosts] {2} scanning  {3} ports found{4}  elapsed {5}" -f `
                $completed, $total, $pending.Count, $totalPortsFound, $portInfo, $elapsed
            script:Write-LineAt -Row $row -Text $statusLine -Fg ([ConsoleColor]::Yellow)
        }
        $row++

        # Hint line
        script:Write-LineAt -Row $row -Text "  Press [E] to end scan early" -Fg ([ConsoleColor]::DarkGray)

        # --- Check for early-exit keypress ---
        $earlyExit = $false
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq [System.ConsoleKey]::E) {
                # Show confirmation on the hint line
                script:Write-LineAt -Row $row -Text "  End scan early? Press [Y] to confirm, any other key to continue" -Fg ([ConsoleColor]::White) -Bg ([ConsoleColor]::DarkRed)
                $confirm = [Console]::ReadKey($true)
                if ($confirm.Key -eq [System.ConsoleKey]::Y) {
                    $earlyExit = $true
                }
            }
        }

        if ($earlyExit) {
            # Harvest partial results from progressState for still-running hosts
            foreach ($pJob in $pending) {
                $jobIP = $pJob.IP
                $completed++
                # Check if progressState has partial port data for this host
                try {
                    $partial = $progressState[$jobIP]
                    if ($partial -and $partial.OpenPorts -and $partial.OpenPorts.Count -gt 0) {
                        $partialResult = @{
                            IP        = $jobIP
                            Alive     = $true
                            OpenPorts = @($partial.OpenPorts)
                            Hostname  = ""
                            OS        = ""
                            TTL       = 0
                        }
                        [void]$liveHosts.Add($partialResult)
                        $portCount = $partial.OpenPorts.Count
                        $pctDone = [Math]::Round(($partial.Scanned / $partial.Total) * 100)
                        $line = "  [{0}/{1}] [~] {2,-15} PARTIAL {3} port(s) ({4}% scanned)" -f `
                            $completed, $total, $jobIP, $portCount, $pctDone
                        [void]$hostResultBuf.Add(@{ Text = $line; Color = [ConsoleColor]::DarkYellow })
                    } else {
                        $line = "  [{0}/{1}] [~] {2,-15} SKIPPED (scan ended early)" -f $completed, $total, $jobIP
                        [void]$hostResultBuf.Add(@{ Text = $line; Color = [ConsoleColor]::DarkGray })
                    }
                } catch {
                    $line = "  [{0}/{1}] [~] {2,-15} SKIPPED (scan ended early)" -f $completed, $total, $jobIP
                    [void]$hostResultBuf.Add(@{ Text = $line; Color = [ConsoleColor]::DarkGray })
                }
                try { $pJob.PowerShell.Stop() } catch {}
                try { $pJob.PowerShell.Dispose() } catch {}
            }
            $pending.Clear()

            # Final redraw with partial results
            $row = $anchorY
            $hStart = [Math]::Max(0, $hostResultBuf.Count - $hostWinSize)
            for ($h = 0; $h -lt $hostWinSize; $h++) {
                $idx = $hStart + $h
                if ($idx -lt $hostResultBuf.Count) {
                    $e = $hostResultBuf[$idx]
                    script:Write-LineAt -Row $row -Text $e.Text -Fg $e.Color
                } else {
                    script:Write-LineAt -Row $row -Text ""
                }
                $row++
            }
            $portHeader = "  -- Open ports ($totalPortsFound found) --"
            script:Write-LineAt -Row $row -Text $portHeader -Fg ([ConsoleColor]::DarkCyan)
            $row++
            $pStart = [Math]::Max(0, $portBuf.Count - $portWinSize)
            for ($p = 0; $p -lt $portWinSize; $p++) {
                $idx = $pStart + $p
                if ($idx -lt $portBuf.Count) {
                    script:Write-LineAt -Row $row -Text $portBuf[$idx] -Fg ([ConsoleColor]::Cyan)
                } else {
                    script:Write-LineAt -Row $row -Text ""
                }
                $row++
            }
            script:Write-LineAt -Row $row -Text "  Scan ended early by user." -Fg ([ConsoleColor]::Yellow)
            Write-Log "Discovery ended early by user. $completed/$total hosts processed, $totalPortsFound ports found." "WARN" -Silent
            $row++
            script:Write-LineAt -Row $row -Text ""
            break
        }

        Start-Sleep -Milliseconds 250
    }
    } finally {
        [Console]::CursorVisible = $true
    }

    # Move cursor below display block and print final summary
    [Console]::SetCursorPosition(0, $anchorY + $displayRows)
    $totalElapsed = ([DateTime]::Now - $startTime).ToString("mm\:ss")
    $partialTag = if ($completed -lt $total) { " (partial)" } else { "" }
    Write-Host "  Discovery complete$partialTag`: $($liveHosts.Count) alive hosts ($totalPortsFound open ports) from $total IPs in $totalElapsed." -ForegroundColor Green

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

    # Build test matrix: each target x each plugin, scoped to relevant ports only
    $testQueue = [System.Collections.ArrayList]::new()
    foreach ($target in $Targets) {
        foreach ($plugin in $SelectedPlugins) {
            $ports = @()
            if ($target.Port) {
                # Specific port provided (Validate mode -- exact IP:port combo)
                $ports = @($target.Port)
            } elseif ($plugin.ScanPorts -and $plugin.ScanPorts.Count -gt 0) {
                # Plugin declares specific ports it cares about.
                # Test plugin's ScanPorts + any discovered open ports that overlap.
                $pluginPortSet = @{}
                foreach ($p in $plugin.ScanPorts) { $pluginPortSet[[int]$p] = $true }
                # Also include discovered open ports that the plugin wants to check
                # (the plugin's ScanPorts are always tested, discovered or not)
                $ports = @($pluginPortSet.Keys | Sort-Object)
                # Additionally, add any discovered open ports that the plugin is
                # relevant for. For now, just test the plugin's declared ports.
                # The plugin's TestBlock handles unreachable ports gracefully.
            } else {
                # Software-class plugin (ScanPorts is empty).
                # Run once per host with port 0 as a sentinel.
                $ports = @(0)
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

    # Collect results via polling (real-time output as each test completes)
    $findings = [System.Collections.ArrayList]::new()
    $completed = 0
    $total = $testQueue.Count
    $pending = [System.Collections.ArrayList]::new($jobs)
    $spinChars = @('|', '/', '-', '\')
    $spinIdx = 0
    $startTime = [DateTime]::Now

    while ($pending.Count -gt 0) {
        for ($i = $pending.Count - 1; $i -ge 0; $i--) {
            $job = $pending[$i]
            if ($job.Handle.IsCompleted) {
                # Clear progress line before printing result
                Write-Host "`r                                                                        `r" -NoNewline
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
                        $detailStr = if ($r.Detail -and $r.Detail.Length -gt 80) { $r.Detail.Substring(0,77) + "..." } elseif ($r.Detail) { $r.Detail } else { "" }
                        $targetStr = if ($r.Port -and $r.Port -ne '0') { "{0}:{1}" -f $r.IP, $r.Port } else { $r.IP }
                        Write-Host ("  [{0}/{1}] {2,-8} {3} ({4}) -- {5}" -f `
                            $completed, $total, $symbol, $targetStr, $r.PluginName, $detailStr
                        ) -ForegroundColor $color
                        # Full detail to log (no truncation)
                        $logDetail = if ($r.Detail) { $r.Detail } else { "" }
                        $logLevel = switch ($r.Result) { "Vulnerable" { "WARN" }; "Error" { "ERROR" }; default { "INFO" } }
                        Write-Log "$($r.Result) $targetStr ($($r.PluginName)) -- $logDetail" $logLevel
                    } else {
                        $completed++
                    }
                } catch {
                    $completed++
                }
                $job.PowerShell.Dispose()
                $pending.RemoveAt($i)
            }
        }
        if ($pending.Count -gt 0) {
            $elapsed = ([DateTime]::Now - $startTime).ToString("mm\:ss")
            $spin = $spinChars[$spinIdx % $spinChars.Count]
            $spinIdx++
            Write-Host ("`r  $spin  [{0}/{1} complete] {2} tests running... elapsed {3}   " -f $completed, $total, $pending.Count, $elapsed) -NoNewline -ForegroundColor Yellow
            Start-Sleep -Milliseconds 250
        }
    }
    # Clear progress line
    Write-Host "`r                                                                        `r" -NoNewline

    $pool.Close()
    $pool.Dispose()

    return $findings
}

# ============================================================
#  SOFTWARE VERSION CHECK ENGINE
# ============================================================

function Invoke-SoftwareCheck {
    <#
    .SYNOPSIS
        Enumerates installed software on Windows hosts and applies flag rules.
        Returns findings in the same format as Invoke-PluginScan for merging.
    #>
    param(
        [array]$Targets,         # Array of @{ IP; Hostname; OS; OpenPorts }
        [array]$FlagRules,       # Array of @{ Pattern; VersionRule; Label }
        [string[]]$SoftwareFilters,  # Wildcard patterns for inventory filtering
        [int]$MaxThreads,
        [PSCredential]$Credential,
        [string]$OutDir
    )

    # Filter to Windows hosts only (by OS guess or port 445 open)
    $windowsTargets = @($Targets | Where-Object {
        ($_.OS -and $_.OS -like "*Windows*") -or
        ($_.OpenPorts -and @($_.OpenPorts) -contains 445)
    })

    if ($windowsTargets.Count -eq 0) {
        Write-Log "Software Check: No Windows hosts detected. Skipping." "WARN"
        return @()
    }

    Write-Log "Software Check: $($windowsTargets.Count) Windows hosts, $($FlagRules.Count) flag rules"
    if ($FlagRules.Count -gt 0) {
        foreach ($rule in $FlagRules) {
            $labelStr = if ($rule.Label) { " [$($rule.Label)]" } else { "" }
            Write-Log "  Rule: $($rule.Pattern)  version: $($rule.VersionRule)$labelStr"
        }
    }

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($MaxThreads, 10))
    $pool.Open()
    $jobs = [System.Collections.ArrayList]::new()

    foreach ($target in $windowsTargets) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool

        [void]$ps.AddScript(@"
$($script:SoftwareHelperString)
$($script:VersionHelperString)

param(`$IP, `$Hostname, `$FlagRulesJson, `$SoftwareFiltersJson, `$Cred)

`$flagRules = @()
if (`$FlagRulesJson) {
    `$flagRules = `$FlagRulesJson | ConvertFrom-Json
}
`$softwareFilters = @()
if (`$SoftwareFiltersJson) {
    `$softwareFilters = `$SoftwareFiltersJson | ConvertFrom-Json
}

# Enumerate software: Registry -> PSRemoting -> WMI
`$hostSoftware = @()
`$method = "None"

`$hostSoftware = @(Get-SoftwareFromRegistry -ComputerName `$IP)
`$method = "Registry"

if (`$hostSoftware.Count -eq 0) {
    `$hostSoftware = @(Get-SoftwareFromPSRemoting -ComputerName `$IP -Credential `$Cred)
    `$method = "PSRemoting"
}

if (`$hostSoftware.Count -eq 0) {
    `$hostSoftware = @(Get-SoftwareFromWMI -ComputerName `$IP -Credential `$Cred)
    `$method = "WMI"
}

# Deduplicate by Name+Version
`$hostSoftware = @(`$hostSoftware | Sort-Object Name, Version -Unique)

# Build results
`$results = [System.Collections.Generic.List[PSObject]]::new()

# Inventory entry (always return count)
`$results.Add(@{
    Type       = 'Inventory'
    IP         = `$IP
    Hostname   = `$Hostname
    Method     = `$method
    TotalCount = `$hostSoftware.Count
    Software   = `$hostSoftware
})

# Apply flag rules
foreach (`$rule in `$flagRules) {
    `$matching = @(`$hostSoftware | Where-Object { `$_.Name -like `$rule.Pattern })
    foreach (`$sw in `$matching) {
        `$isFlagged = Test-VersionAgainstRule -Version `$sw.Version -Rule `$rule.VersionRule
        `$statusMsg = Get-VersionStatus -Version `$sw.Version -Rule `$rule.VersionRule
        `$results.Add(@{
            Type        = 'FlagResult'
            IP          = `$IP
            Hostname    = `$Hostname
            SoftwareName = `$sw.Name
            Version     = `$sw.Version
            Architecture = `$sw.Architecture
            InstallPath = `$sw.InstallPath
            Publisher   = `$sw.Publisher
            FlagPattern = `$rule.Pattern
            FlagRule    = `$rule.VersionRule
            FlagLabel   = `$rule.Label
            IsFlagged   = `$isFlagged
            StatusMsg   = `$statusMsg
            Method      = `$method
        })
    }
}

return `$results
"@)
        # Pass arguments via AddArgument (credentials as live objects)
        [void]$ps.AddArgument($target.IP)
        [void]$ps.AddArgument($target.Hostname)
        [void]$ps.AddArgument(($FlagRules | ConvertTo-Json -Compress -Depth 3))
        [void]$ps.AddArgument(($SoftwareFilters | ConvertTo-Json -Compress -Depth 3))
        [void]$ps.AddArgument($Credential)

        $handle = $ps.BeginInvoke()
        [void]$jobs.Add(@{ PowerShell = $ps; Handle = $handle; IP = $target.IP; Hostname = $target.Hostname })
    }

    # Collect results with real-time output
    $allInventory = [System.Collections.Generic.List[PSObject]]::new()
    $allFlagged = [System.Collections.Generic.List[PSObject]]::new()
    $allFlagResults = [System.Collections.Generic.List[PSObject]]::new()
    $findings = [System.Collections.ArrayList]::new()
    $completed = 0
    $total = $jobs.Count
    $pending = [System.Collections.ArrayList]::new($jobs)
    $spinChars = @('|', '/', '-', '\')
    $spinIdx = 0
    $startTime = [DateTime]::Now

    while ($pending.Count -gt 0) {
        for ($i = $pending.Count - 1; $i -ge 0; $i--) {
            $job = $pending[$i]
            if ($job.Handle.IsCompleted) {
                Write-Host "`r                                                                        `r" -NoNewline
                try {
                    $output = $job.PowerShell.EndInvoke($job.Handle)
                    if ($output) {
                        foreach ($item in $output) {
                            if ($item.Type -eq 'Inventory') {
                                $allInventory.Add($item)
                                $completed++
                                $color = if ($item.TotalCount -gt 0) { "Gray" } else { "DarkYellow" }
                                $countStr = if ($item.TotalCount -gt 0) { "$($item.TotalCount) apps via $($item.Method)" } else { "no software retrieved" }
                                Write-Host ("  [{0}/{1}] {2} ({3}) -- {4}" -f $completed, $total, $item.IP, $item.Hostname, $countStr) -ForegroundColor $color
                                Write-Log "SoftwareCheck $($item.IP) ($($item.Hostname)) -- $countStr" "INFO"
                            }
                            elseif ($item.Type -eq 'FlagResult') {
                                $allFlagResults.Add($item)
                                if ($item.IsFlagged) {
                                    $allFlagged.Add($item)
                                    $labelStr = if ($item.FlagLabel) { " [$($item.FlagLabel)]" } else { "" }
                                    Write-Host ("    *** FLAGGED *** {0} -- {1} v{2} ({3}){4}" -f $item.IP, $item.SoftwareName, $item.Version, $item.FlagRule, $labelStr) -ForegroundColor Red
                                    Write-Log "FLAGGED $($item.IP) -- $($item.SoftwareName) v$($item.Version) ($($item.FlagRule))$labelStr" "WARN"

                                    # Add as a finding for merging with plugin results
                                    [void]$findings.Add(@{
                                        IP         = $item.IP
                                        Port       = '0'
                                        Hostname   = $item.Hostname
                                        PluginName = 'SoftwareVersionCheck'
                                        Result     = 'Vulnerable'
                                        Detail     = "$($item.SoftwareName) v$($item.Version) -- $($item.StatusMsg)$labelStr"
                                    })
                                }
                            }
                        }
                    }
                } catch {
                    $completed++
                    Write-Host ("  [{0}/{1}] {2} -- Error: {3}" -f $completed, $total, $job.IP, $_.Exception.Message) -ForegroundColor Red
                }
                $job.PowerShell.Dispose()
                $pending.RemoveAt($i)
            }
        }
        if ($pending.Count -gt 0) {
            $elapsed = ([DateTime]::Now - $startTime).ToString("mm\:ss")
            $spin = $spinChars[$spinIdx % $spinChars.Count]
            $spinIdx++
            Write-Host ("`r  $spin  [{0}/{1} complete] {2} hosts scanning... elapsed {3}   " -f $completed, $total, $pending.Count, $elapsed) -NoNewline -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
        }
    }
    Write-Host "`r                                                                        `r" -NoNewline

    $pool.Close()
    $pool.Dispose()

    # Summary
    $flaggedCount = $allFlagged.Count
    $okCount = ($allFlagResults | Where-Object { -not $_.IsFlagged }).Count
    $totalElapsed = ([DateTime]::Now - $startTime).ToString("mm\:ss")
    Write-Host "  Software Check complete: $($windowsTargets.Count) hosts scanned, $flaggedCount flagged, $okCount OK in $totalElapsed." -ForegroundColor Green
    Write-Log "Software Check complete: $($windowsTargets.Count) hosts, $flaggedCount flagged, $okCount OK"

    # Export software-specific outputs
    if ($OutDir) {
        Export-SoftwareOutputs -AllInventory $allInventory -AllFlagged $allFlagged `
                               -AllFlagResults $allFlagResults -FlagRules $FlagRules `
                               -SoftwareFilters $SoftwareFilters -OutDir $OutDir
    }

    return $findings
}

# ============================================================
#  SOFTWARE-SPECIFIC OUTPUT FUNCTIONS
# ============================================================

function Export-SoftwareOutputs {
    param(
        [System.Collections.Generic.List[PSObject]]$AllInventory,
        [System.Collections.Generic.List[PSObject]]$AllFlagged,
        [System.Collections.Generic.List[PSObject]]$AllFlagResults,
        [array]$FlagRules,
        [string[]]$SoftwareFilters,
        [string]$OutDir
    )

    $ts = $script:Timestamp

    # Full software inventory CSV
    # Stamp each software entry with the parent inventory IP/Hostname since
    # ComputerName can be lost during RunspacePool deserialization
    $allSoftware = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($inv in $AllInventory) {
        if ($inv.Software) {
            foreach ($sw in $inv.Software) {
                $sw | Add-Member -NotePropertyName ComputerName -NotePropertyValue $inv.IP -Force
                $allSoftware.Add($sw)
            }
        }
    }

    # Use flag rule patterns as implicit software filters when no explicit
    # filters were provided, so the inventory CSVs only contain relevant entries
    $effectiveFilters = $SoftwareFilters
    if ((-not $effectiveFilters -or $effectiveFilters.Count -eq 0) -and $FlagRules -and $FlagRules.Count -gt 0) {
        $effectiveFilters = @($FlagRules | ForEach-Object { $_.Pattern })
    }

    if ($allSoftware.Count -gt 0) {
        # Apply effective filters to the inventory if available
        $exportSoftware = $allSoftware
        if ($effectiveFilters -and $effectiveFilters.Count -gt 0) {
            $exportSoftware = @($allSoftware | Where-Object {
                $name = $_.Name
                $matchesAny = $false
                foreach ($f in $effectiveFilters) {
                    if ($name -like $f) { $matchesAny = $true; break }
                }
                $matchesAny
            })
        }

        if ($exportSoftware.Count -gt 0) {
            $invPath = Join-Path $OutDir "SoftwareInventory_ALL_$ts.csv"
            $exportSoftware | Sort-Object ComputerName, Name |
                Select-Object ComputerName, Name, Version, Publisher, InstallDate, InstallPath, Architecture, Source |
                Export-Csv -Path $invPath -NoTypeInformation -Encoding UTF8
            $filterNote = if ($effectiveFilters -and $effectiveFilters.Count -gt 0) { " (filtered by $($effectiveFilters.Count) pattern(s))" } else { "" }
            Write-Log "Software inventory: $invPath ($($exportSoftware.Count) entries)$filterNote"
        } else {
            Write-Log "Software inventory: no entries matched filters" "WARN"
        }
    }

    # Flagged software outputs
    if ($AllFlagged.Count -gt 0) {
        # Master flagged CSV
        $masterFlagPath = Join-Path $OutDir "FLAGGED_ALL_TARGETS_$ts.csv"
        $flaggedRows = $AllFlagged | ForEach-Object {
            [PSCustomObject]@{
                ComputerName = $_.IP
                Hostname     = $_.Hostname
                SoftwareName = $_.SoftwareName
                Version      = $_.Version
                Architecture = $_.Architecture
                InstallPath  = $_.InstallPath
                FlagRule     = $_.FlagRule
                FlagPattern  = $_.FlagPattern
                FlagLabel    = $_.FlagLabel
                Status       = "FLAGGED"
            }
        }
        $flaggedRows | Sort-Object FlagPattern, ComputerName, SoftwareName |
            Export-Csv -Path $masterFlagPath -NoTypeInformation -Encoding UTF8
        Write-Log "Master flagged CSV: $masterFlagPath ($($AllFlagged.Count) entries)"

        # Master flagged IP list
        $masterIpPath = Join-Path $OutDir "FLAGGED_ALL_IPs_$ts.txt"
        ($AllFlagged | Select-Object -ExpandProperty IP -Unique) |
            Out-File -FilePath $masterIpPath -Encoding UTF8
        Write-Log "Master flagged IPs: $masterIpPath"

        # Per-rule CSVs
        $ruleGroups = $AllFlagged | Group-Object { "$($_.FlagPattern)|$($_.FlagRule)" }
        foreach ($rg in $ruleGroups) {
            $firstEntry = $rg.Group | Select-Object -First 1
            $safeName = ($firstEntry.FlagPattern -replace '[\\/*?<>|":]','_' -replace '^\*','').Trim('_*. ')
            if (-not $safeName) { $safeName = "rule" }

            $rulePath = Join-Path $OutDir "FLAGGED_${safeName}_TARGETS_$ts.csv"
            $rg.Group | ForEach-Object {
                [PSCustomObject]@{
                    ComputerName = $_.IP
                    Hostname     = $_.Hostname
                    SoftwareName = $_.SoftwareName
                    Version      = $_.Version
                    Architecture = $_.Architecture
                    InstallPath  = $_.InstallPath
                    FlagRule     = $_.FlagRule
                    FlagLabel    = $_.FlagLabel
                }
            } | Export-Csv -Path $rulePath -NoTypeInformation -Encoding UTF8

            $ruleIpPath = Join-Path $OutDir "FLAGGED_${safeName}_IPs_$ts.txt"
            ($rg.Group | Select-Object -ExpandProperty IP -Unique) |
                Out-File -FilePath $ruleIpPath -Encoding UTF8

            Write-Log "Per-rule CSV: $rulePath ($($rg.Count) entries)"
        }
    }
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
        [string]$OutDir,
        [switch]$SoftwareCheckEnabled,
        [array]$FlagRules,
        [string[]]$SoftwareFilters,
        [PSCredential]$Credential
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

    # Phase 2: Software Version Check (conditional)
    $softwareFindings = @()
    if ($SoftwareCheckEnabled) {
        Write-Section "PHASE 2: Software Version Check"
        $softwareFindings = @(Invoke-SoftwareCheck -Targets $targets -FlagRules $FlagRules `
                                                   -SoftwareFilters $SoftwareFilters `
                                                   -MaxThreads $Threads -Credential $Credential `
                                                   -OutDir $OutDir)
    }

    # Phase 3: Vulnerability Scanning (plugin-based)
    $phaseNum = if ($SoftwareCheckEnabled) { 3 } else { 2 }
    if ($SelectedPlugins.Count -gt 0) {
        Write-Section "PHASE ${phaseNum}: Vulnerability Scanning"
        $findings = Invoke-PluginScan -Targets $targets -SelectedPlugins $SelectedPlugins `
                                      -MaxThreads $Threads -TimeoutMs $Timeout
    } else {
        $findings = @()
    }

    # Merge software findings with plugin findings
    $allFindings = @($softwareFindings) + @($findings)

    $outputPhase = $phaseNum + 1
    Write-Section "PHASE ${outputPhase}: Output"
    Export-Results -Findings $allFindings -SelectedOutputs $SelectedOutputs -OutDir $OutDir -Mode "Network Scan"
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
        [int[]]$PortList,
        [string]$OutDir,
        [switch]$SoftwareCheckEnabled,
        [array]$FlagRules,
        [string[]]$SoftwareFilters,
        [PSCredential]$Credential
    )

    Write-Section "PHASE 1: Loading Host List + Port Discovery"

    $lines = Get-Content -Path $HostFilePath | Where-Object { $_ -match '\S' } |
             ForEach-Object { $_.Trim() } | Sort-Object -Unique
    Write-Log "$($lines.Count) unique hosts loaded from $HostFilePath"

    # Run discovery to find open ports, resolve hostnames, guess OS
    $liveHosts = Invoke-HostDiscovery -IPList $lines -MaxThreads $Threads `
                                      -TimeoutMs $Timeout -PortList $PortList
    Write-Log "$($liveHosts.Count) hosts alive of $($lines.Count)" "OK"

    # Export discovery CSV if requested
    if ($SelectedOutputs -contains "DiscoveryCSV") {
        $discPath = Join-Path $OutDir "Discovery_$($script:Timestamp).csv"
        Export-DiscoveryCSV -Hosts $liveHosts -Path $discPath
    }

    if ($liveHosts.Count -eq 0) {
        Write-Log "No live hosts found. Nothing to scan." "WARN"
        return
    }

    $targets = $liveHosts | ForEach-Object {
        @{
            IP        = $_.IP
            Hostname  = $_.Hostname
            OpenPorts = $_.OpenPorts
            OS        = $_.OS
            Port      = $null
        }
    }

    # Phase 2: Software Version Check (conditional)
    $softwareFindings = @()
    if ($SoftwareCheckEnabled) {
        Write-Section "PHASE 2: Software Version Check"
        $softwareFindings = @(Invoke-SoftwareCheck -Targets $targets -FlagRules $FlagRules `
                                                   -SoftwareFilters $SoftwareFilters `
                                                   -MaxThreads $Threads -Credential $Credential `
                                                   -OutDir $OutDir)
    }

    # Phase 3: Vulnerability Scanning (plugin-based)
    $phaseNum = if ($SoftwareCheckEnabled) { 3 } else { 2 }
    if ($SelectedPlugins.Count -gt 0) {
        Write-Section "PHASE ${phaseNum}: Vulnerability Scanning"
        $findings = Invoke-PluginScan -Targets $targets -SelectedPlugins $SelectedPlugins `
                                      -MaxThreads $Threads -TimeoutMs $Timeout
    } else {
        $findings = @()
    }

    # Merge software findings with plugin findings
    $allFindings = @($softwareFindings) + @($findings)

    $outputPhase = $phaseNum + 1
    Write-Section "PHASE ${outputPhase}: Output"
    Export-Results -Findings $allFindings -SelectedOutputs $SelectedOutputs -OutDir $OutDir -Mode "List Scan"
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
        [int[]]$PortList,
        [string]$OutDir
    )

    Write-Section "PHASE 1: Loading OpenVAS CSV"

    $rows = Import-OpenVASCSV -Path $CSVPath
    Write-Log "$($rows.Count) findings loaded"

    # Extract unique IPs from the CSV and run discovery for host details
    $uniqueIPs = @($rows | ForEach-Object {
        (($_.ip.Trim() -split '\.') | ForEach-Object { [int]$_ }) -join '.'
    } | Sort-Object -Unique)
    Write-Log "$($uniqueIPs.Count) unique IPs in CSV"

    $liveHosts = Invoke-HostDiscovery -IPList $uniqueIPs -MaxThreads $Threads `
                                      -TimeoutMs $Timeout -PortList $PortList
    Write-Log "$($liveHosts.Count) hosts alive of $($uniqueIPs.Count)" "OK"

    # Export discovery CSV if requested
    if ($SelectedOutputs -contains "DiscoveryCSV") {
        $discPath = Join-Path $OutDir "Discovery_$($script:Timestamp).csv"
        Export-DiscoveryCSV -Hosts $liveHosts -Path $discPath
    }

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

    Write-Section "PHASE 2: Validating Findings"

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

    Write-Section "PHASE 3: Output"

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

# --- Resolve threads/timeout defaults ---
$threads = if ($MaxThreads -gt 0) { $MaxThreads } elseif ($script:Config.DefaultThreads) { $script:Config.DefaultThreads } else { 20 }
$timeout = if ($TimeoutMs -gt 0) { $TimeoutMs } elseif ($script:Config.DefaultTimeoutMs) { $script:Config.DefaultTimeoutMs } else { 5000 }
$portStr = if ($Ports) { $Ports } elseif ($script:Config.DefaultPorts) { $script:Config.DefaultPorts } else { "" }

# --- Determine mode from CLI flags ---
$mode = ""
if ($Scan)     { $mode = "Scan" }
if ($List)     { $mode = "List" }
if ($Validate) { $mode = "Validate" }

# ============================================================
#  NON-INTERACTIVE PATH (-NoMenu or mode specified via CLI)
# ============================================================
if ($mode -and $NoMenu) {
    # --- Plugin selection (CLI) ---
    $selectedPlugins = @()
    $softwareCheckEnabled = $false
    if ($Plugins) {
        $pluginNames = $Plugins -split ',' | ForEach-Object { $_.Trim() }
        # Check for SoftwareVersionCheck in plugin list
        if ($pluginNames -contains 'SoftwareVersionCheck') {
            $softwareCheckEnabled = $true
            $pluginNames = @($pluginNames | Where-Object { $_ -ne 'SoftwareVersionCheck' })
        }
        $selectedPlugins = $script:Validators | Where-Object { $pluginNames -contains $_.Name }
    } else {
        $selectedPlugins = $script:Validators
    }

    # Auto-enable software check if flag parameters provided
    if ($FlagFilter -or $FlagFilterFile) {
        $softwareCheckEnabled = $true
    }

    if ($selectedPlugins.Count -eq 0 -and -not $softwareCheckEnabled) {
        Write-Log "No plugins selected." "ERROR"
        exit 1
    }

    # --- Parse flag rules (CLI) ---
    $cliFlagRules = @()
    if ($softwareCheckEnabled) {
        $cliFlagRules = @(Import-FlagRules -FlagFilter $FlagFilter -FlagVersion $FlagVersion `
                                           -FlagLabel $FlagLabel -FlagFilterFile $FlagFilterFile)
        if ($cliFlagRules.Count -gt 0) {
            Write-Log "Flag rules ($($cliFlagRules.Count)):"
            foreach ($rule in $cliFlagRules) {
                $labelStr = if ($rule.Label) { " [$($rule.Label)]" } else { "" }
                Write-Log "  $($rule.Pattern)  version: $($rule.VersionRule)$labelStr"
            }
        }
    }

    # --- Parse software filters (CLI) ---
    $cliSoftwareFilters = @()
    if ($SoftwareFilter) {
        $cliSoftwareFilters = @($SoftwareFilter -split ',' | ForEach-Object { $_.Trim() })
    }
    if ($SoftwareFilterFile -and (Test-Path $SoftwareFilterFile)) {
        $fileFilters = @(Get-Content $SoftwareFilterFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() })
        $cliSoftwareFilters = @($cliSoftwareFilters) + @($fileFilters)
    }

    # --- Output selection (CLI) ---
    $selectedOutputs = @()
    if ($Outputs) {
        $selectedOutputs = $Outputs -split ',' | ForEach-Object { $_.Trim() }
    } else {
        $selectedOutputs = @("MasterCSV", "SummaryReport")
    }

    Write-Log "Mode: $mode"
    $pluginDisplay = @($selectedPlugins | ForEach-Object { $_.Name })
    if ($softwareCheckEnabled) { $pluginDisplay = @("SoftwareVersionCheck") + $pluginDisplay }
    Write-Log ("Plugins: {0}" -f ($pluginDisplay -join ', '))

    # --- Mode-specific input gathering and execution (CLI) ---
    switch ($mode) {
        "Scan" {
            $cidrList = @()
            if ($CIDRs) {
                $cidrList = $CIDRs -split ',' | ForEach-Object { $_.Trim() }
            } elseif ($CIDRFile -and (Test-Path $CIDRFile)) {
                $cidrList = Get-Content $CIDRFile | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
            }
            if ($cidrList.Count -eq 0) {
                Write-Log "No CIDRs provided." "ERROR"
                exit 1
            }

            $swOnly = ($softwareCheckEnabled -and $selectedPlugins.Count -eq 0)
            $portList = Build-PortList -PortString $portStr -SelectedPlugins $selectedPlugins -SoftwareCheckOnly:$swOnly

            Save-Config
            Invoke-ScanMode -CIDRList $cidrList -SelectedPlugins $selectedPlugins `
                            -SelectedOutputs $selectedOutputs -Threads $threads `
                            -Timeout $timeout -PortList $portList -OutDir $outDir `
                            -SoftwareCheckEnabled:$softwareCheckEnabled `
                            -FlagRules $cliFlagRules -SoftwareFilters $cliSoftwareFilters `
                            -Credential $Credential
        }
        "List" {
            if (-not $HostFile -or -not (Test-Path $HostFile)) {
                Write-Log "No valid host file provided." "ERROR"
                exit 1
            }
            $swOnly = ($softwareCheckEnabled -and $selectedPlugins.Count -eq 0)
            $portList = Build-PortList -PortString $portStr -SelectedPlugins $selectedPlugins -SoftwareCheckOnly:$swOnly

            Save-Config
            Invoke-ListMode -HostFilePath $HostFile -SelectedPlugins $selectedPlugins `
                            -SelectedOutputs $selectedOutputs -Threads $threads `
                            -Timeout $timeout -PortList $portList -OutDir $outDir `
                            -SoftwareCheckEnabled:$softwareCheckEnabled `
                            -FlagRules $cliFlagRules -SoftwareFilters $cliSoftwareFilters `
                            -Credential $Credential
        }
        "Validate" {
            if (-not $InputCSV -or -not (Test-Path $InputCSV)) {
                Write-Log "No valid CSV file provided." "ERROR"
                exit 1
            }
            $portList = Build-PortList -PortString $portStr -SelectedPlugins $selectedPlugins

            Save-Config
            Invoke-ValidateMode -CSVPath $InputCSV -SelectedPlugins $selectedPlugins `
                                -SelectedOutputs $selectedOutputs -Threads $threads `
                                -Timeout $timeout -PortList $portList -OutDir $outDir
        }
    }

    Save-Config
    Write-Host ""
    Write-Host "  ScottyScan complete." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# ============================================================
#  INTERACTIVE PATH - State Machine with Back-Navigation
# ============================================================
#  Step 1: Mode select               -> Esc = exit
#  Step 2: Plugin select             -> Esc = back to 1
#  Step 3: Flag rules config (cond.) -> Esc = back to 2
#  Step 4: Credential prompt (cond.) -> Esc = back to 3 (or 2)
#  Step 5: Output select             -> Esc = back to 4
#  Step 6: Settings                  -> Esc = back to 5
#  Step 7: Mode-specific input       -> Esc = back to 6
#  Step 8: Confirmation screen       -> Esc = back to 7, Enter = execute
# ============================================================

$step = 1
# Accumulate selections across steps so back-navigation preserves choices
$selectedMode         = $mode  # may be pre-set from CLI flag without -NoMenu
$selectedPlugins      = @()
$selectedOutputs      = @()
$modeInputData        = $null
$softwareCheckEnabled = $false
$interactiveFlagRules = @()
$interactiveSoftwareFilters = @()
$interactiveCredential = $Credential  # may be pre-set from CLI -Credential param

while ($step -ge 1 -and $step -le 8) {

    switch ($step) {

        # ---- STEP 1: Mode Selection ----
        1 {
            if ($selectedMode) {
                # Mode was set via CLI flag (e.g. -Scan without -NoMenu) -- skip menu
                $step = 2
                continue
            }

            $lastMode = $script:Config.LastMode
            $modeItems = @(
                @{ Name = "Network Scan"; Value = "Scan";     Selected = ($lastMode -eq "Scan");     Description = "Discover hosts on CIDRs and scan for vulnerabilities" }
                @{ Name = "List Scan";    Value = "List";     Selected = ($lastMode -eq "List");     Description = "Scan specific hosts from a file" }
                @{ Name = "Validate";     Value = "Validate"; Selected = ($lastMode -eq "Validate"); Description = "Validate OpenVAS findings against live hosts" }
            )
            if (-not $lastMode) { $modeItems[0].Selected = $true }

            $modeResult = Show-InteractiveMenu -Title "What would you like to do?" -Items $modeItems -SingleSelect -IsRootMenu
            if ($null -eq $modeResult) {
                # Escape at step 1 = exit
                if (Test-IsConsoleHost) {
                    Clear-Host
                    try { [Console]::CursorVisible = $true } catch {}
                }
                Write-Host ""
                Write-Host "  Cancelled." -ForegroundColor Yellow
                Write-Host ""
                exit 0
            }
            $selectedMode = $modeResult | Select-Object -First 1
            if (-not $selectedMode) {
                continue
            }
            Update-ConfigValue "LastMode" $selectedMode
            $step = 2
        }

        # ---- STEP 2: Plugin Selection (with Software Version Check) ----
        2 {
            if ($Plugins) {
                # CLI plugin filter active -- skip menu
                $pluginNames = $Plugins -split ',' | ForEach-Object { $_.Trim() }
                if ($pluginNames -contains 'SoftwareVersionCheck') {
                    $softwareCheckEnabled = $true
                    $pluginNames = @($pluginNames | Where-Object { $_ -ne 'SoftwareVersionCheck' })
                }
                $selectedPlugins = $script:Validators | Where-Object { $pluginNames -contains $_.Name }
                $step = 3
                continue
            }

            # Build plugin menu items -- prepend Software Version Check
            $swCheckDefault = ($script:Config.DefaultPlugins -contains "__SoftwareVersionCheck__")
            $pluginItems = @(
                @{
                    Name        = "Software Version Check"
                    Value       = "__SoftwareVersionCheck__"
                    Selected    = $swCheckDefault
                    Description = "Inventory software on Windows hosts, flag vulnerable versions"
                }
            )
            $pluginItems += @($script:Validators | ForEach-Object {
                $isDefault = ($script:Config.DefaultPlugins.Count -eq 0) -or ($script:Config.DefaultPlugins -contains $_.Name)
                @{
                    Name        = $_.Name
                    Value       = $_.Name
                    Selected    = $isDefault
                    Description = $_.Description
                }
            })
            $selectedNames = Show-InteractiveMenu -Title "Which plugins to run?" -Items $pluginItems -AllowSelectAll
            if ($null -eq $selectedNames) {
                # Back to mode select
                if (-not $mode) { $selectedMode = "" }
                $step = 1
                continue
            }

            # Separate software check from real plugins
            $softwareCheckEnabled = ($selectedNames -contains "__SoftwareVersionCheck__")
            $realPluginNames = @($selectedNames | Where-Object { $_ -ne "__SoftwareVersionCheck__" })
            $selectedPlugins = $script:Validators | Where-Object { $realPluginNames -contains $_.Name }

            if ($selectedPlugins.Count -eq 0 -and -not $softwareCheckEnabled) {
                Write-Host "  No plugins selected. Select at least one." -ForegroundColor Red
                continue  # re-show step 2
            }

            $persistNames = @($realPluginNames)
            if ($softwareCheckEnabled) { $persistNames = @("__SoftwareVersionCheck__") + $persistNames }
            Update-ConfigValue "DefaultPlugins" $persistNames
            $step = 3
        }

        # ---- STEP 3: Flag Rules Configuration (conditional) ----
        3 {
            # Only show if Software Version Check is selected AND mode is not Validate
            if (-not $softwareCheckEnabled -or $selectedMode -eq "Validate") {
                # Auto-skip -- nothing to configure
                $step = 4
                continue
            }

            # If CLI flag params provided, use those
            if ($FlagFilter -or $FlagFilterFile) {
                $interactiveFlagRules = @(Import-FlagRules -FlagFilter $FlagFilter -FlagVersion $FlagVersion `
                                                            -FlagLabel $FlagLabel -FlagFilterFile $FlagFilterFile)
                if ($SoftwareFilter) {
                    $interactiveSoftwareFilters = @($SoftwareFilter -split ',' | ForEach-Object { $_.Trim() })
                }
                if ($SoftwareFilterFile -and (Test-Path $SoftwareFilterFile)) {
                    $fileFilters = @(Get-Content $SoftwareFilterFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() })
                    $interactiveSoftwareFilters = @($interactiveSoftwareFilters) + @($fileFilters)
                }
                $step = 4
                continue
            }

            # Interactive flag rules configuration
            # Check for saved rules first to determine default selection
            $savedRules = @()
            $hasSaved = ($script:Config.PSObject.Properties.Name -contains 'SavedFlagRules' -and $script:Config.SavedFlagRules.Count -gt 0)
            $flagConfigItems = @(
                @{ Name = "Load rules from file";  Value = "file";  Selected = $false; Description = "CSV with pattern,version_rule,label per line" }
                @{ Name = "Enter rules manually";  Value = "manual"; Selected = $false; Description = "Type patterns and version thresholds" }
            )

            if ($hasSaved) {
                $savedRules = @($script:Config.SavedFlagRules)
                $savedPreview = ($savedRules | Select-Object -First 2 | ForEach-Object { "$($_.Pattern) $($_.VersionRule)" }) -join '; '
                if ($savedRules.Count -gt 2) { $savedPreview += " (+$($savedRules.Count - 2) more)" }
                $flagConfigItems += @{
                    Name = "Use saved rules ($($savedRules.Count))"; Value = "saved"; Selected = $true
                    Description = $savedPreview
                }
            }

            $flagConfigItems += @{
                Name = "Skip (no flag rules)"; Value = "skip"; Selected = (-not $hasSaved)
                Description = "Run software inventory only, no version flagging"
            }

            $flagChoice = Show-InteractiveMenu -Title "Software Version Check -- Flag rules:" `
                                               -Items $flagConfigItems -SingleSelect
            if ($null -eq $flagChoice) {
                $step = 2
                continue
            }

            $flagPicked = $flagChoice | Select-Object -First 1

            switch ($flagPicked) {
                "file" {
                    $flagHistory = Get-InputHistory -HistoryKey "FlagRuleFileHistory"
                    $flagFilePath = Show-FilePrompt -Title "Flag rules CSV file:" `
                                                    -History $flagHistory `
                                                    -Filter "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*" `
                                                    -TypePrompt "Type the full file path:" `
                                                    -MustExist
                    if (-not $flagFilePath) {
                        continue  # re-show step 3
                    }
                    Push-InputHistory "FlagRuleFileHistory" $flagFilePath
                    $interactiveFlagRules = @(Import-FlagRules -FlagFilterFile $flagFilePath)
                    if ($interactiveFlagRules.Count -eq 0) {
                        Write-Host "  No valid rules found in $flagFilePath" -ForegroundColor Red
                        continue
                    }
                }
                "manual" {
                    # Prompt for patterns
                    $patternStr = Show-TextPrompt -Prompt "Software patterns (comma-separated wildcards, e.g. *notepad*,*putty*):" `
                                                  -LastValue ($script:Config.LastSoftwareFilter)
                    if ([string]::IsNullOrWhiteSpace($patternStr)) { continue }

                    $versionStr = Show-TextPrompt -Prompt "Version rules (positional, e.g. LT8.9.1,LT0.82  or * for any):" `
                                                  -Default "*"
                    $labelStr = Show-TextPrompt -Prompt "Labels (optional, e.g. CVE-2025-15556,CVE-2024-31497):" `
                                                -Default ""

                    $interactiveFlagRules = @(Import-FlagRules -FlagFilter $patternStr -FlagVersion $versionStr -FlagLabel $labelStr)
                    Update-ConfigValue "LastSoftwareFilter" $patternStr
                }
                "saved" {
                    $interactiveFlagRules = @($savedRules | ForEach-Object {
                        [PSCustomObject]@{
                            Pattern     = $_.Pattern
                            VersionRule = $_.VersionRule
                            Label       = $_.Label
                        }
                    })
                }
                "skip" {
                    $interactiveFlagRules = @()
                }
            }

            # Save rules to config for next time
            if ($interactiveFlagRules.Count -gt 0) {
                $rulesToSave = @($interactiveFlagRules | ForEach-Object {
                    @{ Pattern = $_.Pattern; VersionRule = $_.VersionRule; Label = $_.Label }
                })
                Update-ConfigValue "SavedFlagRules" $rulesToSave
            }

            $step = 4
        }

        # ---- STEP 4: Credential Prompt (conditional) ----
        4 {
            # Only prompt if Software Version Check is selected AND mode is not Validate
            # AND no credential was provided via CLI
            if (-not $softwareCheckEnabled -or $selectedMode -eq "Validate") {
                $step = 5
                continue
            }
            if ($Credential) {
                # CLI already provided credentials
                $interactiveCredential = $Credential
                $step = 5
                continue
            }

            $credItems = @(
                @{ Name = "Use current session (domain credentials)"; Value = "session"; Selected = $true;  Description = "Authenticate as $($env:USERDOMAIN)\$($env:USERNAME)" }
                @{ Name = "Enter alternate credentials";              Value = "prompt";  Selected = $false; Description = "Provide username and password for remote access" }
            )
            $credChoice = Show-InteractiveMenu -Title "Credentials for remote software check:" `
                                                -Items $credItems -SingleSelect
            if ($null -eq $credChoice) {
                # Back to step 3 if software check enabled, else step 2
                $step = if ($softwareCheckEnabled -and $selectedMode -ne "Validate") { 3 } else { 2 }
                continue
            }

            $credPicked = $credChoice | Select-Object -First 1
            if ($credPicked -eq "prompt") {
                try {
                    if (Test-IsConsoleHost) {
                        try { [Console]::CursorVisible = $true } catch {}
                    }
                    Write-Host ""
                    Write-Host "  Enter credentials for remote access:" -ForegroundColor Yellow
                    $interactiveCredential = Get-Credential -Message "ScottyScan - Remote Access Credentials"
                    if (Test-IsConsoleHost) {
                        try { [Console]::CursorVisible = $false } catch {}
                    }
                } catch {
                    Write-Host "  Credential entry cancelled. Using current session." -ForegroundColor DarkYellow
                    $interactiveCredential = $null
                }
            } else {
                $interactiveCredential = $null
            }

            $step = 5
        }

        # ---- STEP 5: Output Selection ----
        5 {
            if ($Outputs) {
                $selectedOutputs = $Outputs -split ',' | ForEach-Object { $_.Trim() }
                $step = 6
                continue
            }

            $outputItems = @(
                @{ Name = "Master findings CSV";      Value = "MasterCSV";     Selected = ($script:Config.DefaultOutputs -contains "MasterCSV");     Description = "All findings in one CSV" }
                @{ Name = "Executive summary report"; Value = "SummaryReport"; Selected = ($script:Config.DefaultOutputs -contains "SummaryReport"); Description = "Plain-text report for CAB/exec review" }
                @{ Name = "Per-plugin result CSVs";   Value = "PerPluginCSV";  Selected = ($script:Config.DefaultOutputs -contains "PerPluginCSV");  Description = "Separate CSV per plugin" }
                @{ Name = "Host discovery CSV";       Value = "DiscoveryCSV";  Selected = ($script:Config.DefaultOutputs -contains "DiscoveryCSV");  Description = "Live hosts with open ports, hostname, and OS" }
            )
            $outputResult = Show-InteractiveMenu -Title "Output options:" -Items $outputItems -AllowSelectAll
            if ($null -eq $outputResult) {
                # Back to credential step (4)
                $step = 4
                continue
            }
            $selectedOutputs = @($outputResult)
            Update-ConfigValue "DefaultOutputs" $selectedOutputs
            Update-ConfigValue "LastOutputDir" $outDir
            $step = 6
        }

        # ---- STEP 6: Settings (threads/timeout/ports) ----
        6 {
            $settingsResult = Show-SettingsMenu -CurrentThreads $threads -CurrentTimeout $timeout -CurrentPorts $portStr
            if ($null -eq $settingsResult) {
                $step = 5
                continue
            }
            $threads = $settingsResult.Threads
            $timeout = $settingsResult.Timeout
            $portStr = $settingsResult.Ports
            Update-ConfigValue "DefaultThreads" $threads
            Update-ConfigValue "DefaultTimeoutMs" $timeout
            Update-ConfigValue "DefaultPorts" $portStr
            $step = 7
        }

        # ---- STEP 7: Mode-Specific Input ----
        7 {
            # Check if CLI already provided the needed input
            $cliInputProvided = $false
            switch ($selectedMode) {
                "Scan" {
                    if ($CIDRs -or ($CIDRFile -and (Test-Path $CIDRFile))) { $cliInputProvided = $true }
                }
                "List" {
                    if ($HostFile -and (Test-Path $HostFile)) { $cliInputProvided = $true }
                }
                "Validate" {
                    if ($InputCSV -and (Test-Path $InputCSV)) { $cliInputProvided = $true }
                }
            }

            if ($cliInputProvided) {
                # Build modeInputData from CLI params
                switch ($selectedMode) {
                    "Scan" {
                        $cidrList = @()
                        if ($CIDRs) {
                            $cidrList = $CIDRs -split ',' | ForEach-Object { $_.Trim() }
                        } elseif ($CIDRFile -and (Test-Path $CIDRFile)) {
                            $cidrList = Get-Content $CIDRFile | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
                        }
                        $modeInputData = @{ CIDRList = $cidrList; CIDRFile = $CIDRFile; CIDRs = ($cidrList -join ', ') }
                    }
                    "List"     { $modeInputData = @{ HostFile = $HostFile } }
                    "Validate" { $modeInputData = @{ CSVPath = $InputCSV } }
                }
                $step = 8
                continue
            }

            $modeInputData = Get-ModeInput -Mode $selectedMode -Config $script:Config
            if ($null -eq $modeInputData) {
                $step = 6
                continue
            }

            # Persist to history
            switch ($selectedMode) {
                "Scan" {
                    $histVal = if ($modeInputData.RawInput) { $modeInputData.RawInput }
                               elseif ($modeInputData.CIDRFile) { $modeInputData.CIDRFile }
                               elseif ($modeInputData.CIDRs) { $modeInputData.CIDRs }
                               else { $null }
                    if ($histVal) { Push-InputHistory "CIDRInputHistory" $histVal }
                    if ($modeInputData.CIDRFile) { Update-ConfigValue "LastCIDRFile" $modeInputData.CIDRFile }
                    if ($modeInputData.CIDRs) { Update-ConfigValue "LastCIDRs" $modeInputData.CIDRs }
                }
                "List" {
                    Push-InputHistory "HostFileHistory" $modeInputData.HostFile
                    Update-ConfigValue "LastHostFile" $modeInputData.HostFile
                }
                "Validate" {
                    Push-InputHistory "InputCSVHistory" $modeInputData.CSVPath
                    Update-ConfigValue "LastInputCSV" $modeInputData.CSVPath
                }
            }
            $step = 8
        }

        # ---- STEP 8: Confirmation Screen ----
        8 {
            # Build input detail string for display
            $inputDetail = ""
            switch ($selectedMode) {
                "Scan" {
                    $cidrDisplay = ($modeInputData.CIDRList | Select-Object -First 3) -join ', '
                    if ($modeInputData.CIDRList.Count -gt 3) { $cidrDisplay += " (+$($modeInputData.CIDRList.Count - 3) more)" }
                    $inputDetail = $cidrDisplay
                }
                "List"     { $inputDetail = $modeInputData.HostFile }
                "Validate" { $inputDetail = $modeInputData.CSVPath }
            }

            # Build plugin names for display
            $confirmPluginNames = @($selectedPlugins | ForEach-Object { $_.Name })
            if ($softwareCheckEnabled) {
                $confirmPluginNames = @("Software Version Check") + $confirmPluginNames
            }

            # Build software check detail for confirmation
            $swCheckDetail = ""
            if ($softwareCheckEnabled -and $interactiveFlagRules.Count -gt 0) {
                $rulePreview = ($interactiveFlagRules | Select-Object -First 3 | ForEach-Object {
                    $lbl = if ($_.Label) { " [$($_.Label)]" } else { "" }
                    "$($_.Pattern) $($_.VersionRule)$lbl"
                }) -join '; '
                if ($interactiveFlagRules.Count -gt 3) { $rulePreview += " (+$($interactiveFlagRules.Count - 3) more)" }
                $swCheckDetail = "$($interactiveFlagRules.Count) rule(s): $rulePreview"
            } elseif ($softwareCheckEnabled) {
                $swCheckDetail = "Inventory only (no flag rules)"
            }

            $swOnly = ($softwareCheckEnabled -and $selectedPlugins.Count -eq 0)
            $credDisplay = ""
            if ($softwareCheckEnabled) {
                if ($interactiveCredential) {
                    $credDisplay = $interactiveCredential.UserName
                } else {
                    $credDisplay = "Current session ($($env:USERDOMAIN)\$($env:USERNAME))"
                }
            }
            $confirmed = Show-ConfirmationScreen `
                -Mode $selectedMode `
                -PluginNames $confirmPluginNames `
                -OutputNames $selectedOutputs `
                -Threads $threads `
                -Timeout $timeout `
                -Ports $portStr `
                -InputDetail $inputDetail `
                -SoftwareCheckDetail $swCheckDetail `
                -SoftwareCheckOnly:$swOnly `
                -CredentialDisplay $credDisplay

            if (-not $confirmed) {
                $step = 7
                continue
            }

            # ---- EXECUTE: leave TUI mode, restore normal console ----
            if (Test-IsConsoleHost) {
                Clear-Host
                try { [Console]::CursorVisible = $true } catch {}
            }
            Write-Banner
            Write-Log "Mode: $selectedMode"
            $logPlugins = @($selectedPlugins | ForEach-Object { $_.Name })
            if ($softwareCheckEnabled) { $logPlugins = @("SoftwareVersionCheck") + $logPlugins }
            Write-Log ("Plugins: {0}" -f ($logPlugins -join ', '))
            if ($softwareCheckEnabled) {
                if ($interactiveCredential) {
                    Write-Log "Credentials: $($interactiveCredential.UserName)"
                } else {
                    Write-Log "Credentials: Current session ($($env:USERDOMAIN)\$($env:USERNAME))"
                }
            }
            if ($softwareCheckEnabled -and $interactiveFlagRules.Count -gt 0) {
                Write-Log "Flag rules ($($interactiveFlagRules.Count)):"
                foreach ($rule in $interactiveFlagRules) {
                    $labelStr = if ($rule.Label) { " [$($rule.Label)]" } else { "" }
                    Write-Log "  $($rule.Pattern)  version: $($rule.VersionRule)$labelStr"
                }
            }

            $swOnly = ($softwareCheckEnabled -and $selectedPlugins.Count -eq 0)

            switch ($selectedMode) {
                "Scan" {
                    $cidrList = $modeInputData.CIDRList
                    if ($cidrList.Count -eq 0) {
                        Write-Log "No CIDRs provided." "ERROR"
                        exit 1
                    }
                    $portList = Build-PortList -PortString $portStr -SelectedPlugins $selectedPlugins -SoftwareCheckOnly:$swOnly

                    Save-Config
                    Invoke-ScanMode -CIDRList $cidrList -SelectedPlugins $selectedPlugins `
                                    -SelectedOutputs $selectedOutputs -Threads $threads `
                                    -Timeout $timeout -PortList $portList -OutDir $outDir `
                                    -SoftwareCheckEnabled:$softwareCheckEnabled `
                                    -FlagRules $interactiveFlagRules `
                                    -SoftwareFilters $interactiveSoftwareFilters `
                                    -Credential $interactiveCredential
                }
                "List" {
                    $hostFilePath = $modeInputData.HostFile
                    if (-not $hostFilePath -or -not (Test-Path $hostFilePath)) {
                        Write-Log "No valid host file provided." "ERROR"
                        exit 1
                    }
                    $portList = Build-PortList -PortString $portStr -SelectedPlugins $selectedPlugins -SoftwareCheckOnly:$swOnly

                    Save-Config
                    Invoke-ListMode -HostFilePath $hostFilePath -SelectedPlugins $selectedPlugins `
                                    -SelectedOutputs $selectedOutputs -Threads $threads `
                                    -Timeout $timeout -PortList $portList -OutDir $outDir `
                                    -SoftwareCheckEnabled:$softwareCheckEnabled `
                                    -FlagRules $interactiveFlagRules `
                                    -SoftwareFilters $interactiveSoftwareFilters `
                                    -Credential $interactiveCredential
                }
                "Validate" {
                    $csvPath = $modeInputData.CSVPath
                    if (-not $csvPath -or -not (Test-Path $csvPath)) {
                        Write-Log "No valid CSV file provided." "ERROR"
                        exit 1
                    }
                    $portList = Build-PortList -PortString $portStr -SelectedPlugins $selectedPlugins

                    Save-Config
                    Invoke-ValidateMode -CSVPath $csvPath -SelectedPlugins $selectedPlugins `
                                        -SelectedOutputs $selectedOutputs -Threads $threads `
                                        -Timeout $timeout -PortList $portList -OutDir $outDir
                }
            }

            # Done -- break out of the state machine
            $step = 9
        }
    }
}

if (-not $mode -and -not $selectedMode) {
    Write-Log "No mode specified. Use -Scan, -List, or -Validate (or run without -NoMenu for interactive)." "ERROR"
    exit 1
}

Save-Config
Write-Host ""
Write-Host "  ScottyScan complete." -ForegroundColor Green
Write-Host ""
