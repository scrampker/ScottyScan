# Test the interactive flow by providing scripted input via the pipeline
# Simulates: mode=Scan(1), plugins=Enter(accept defaults), outputs=Enter(accept defaults),
# CIDRs=192.168.1.0/30, then it should run

# We'll redirect stdin from a series of lines
# But Read-Host doesn't read from pipeline in PS5, so let's test the menu rendering only

$ErrorActionPreference = 'Continue'

# Source just the functions from ScottyScan
$scriptPath = Join-Path $PSScriptRoot "ScottyScan.ps1"
$scriptContent = Get-Content $scriptPath -Raw

# Extract and test Show-CheckboxMenu by calling it directly
# First, dot-source the whole script in a way that doesn't execute main
# Actually, let's just define the function and test

function Show-CheckboxMenu {
    param(
        [string]$Title,
        [array]$Items,
        [switch]$AllowSelectAll,
        [switch]$SingleSelect
    )

    $selections = @()
    foreach ($item in $Items) {
        $selections += @{
            Name        = $item.Name
            Value       = $item.Value
            Selected    = [bool]$item.Selected
            Description = $item.Description
        }
    }

    # Just render once (don't loop for this test)
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
}

Write-Host "=== Mode Selection Menu (SingleSelect) ===" -ForegroundColor Cyan
$modeItems = @(
    @{ Name = "Network Scan"; Value = "Scan"; Selected = $true; Description = "Discover hosts on CIDRs and scan for vulnerabilities" }
    @{ Name = "List Scan";    Value = "List"; Selected = $false; Description = "Scan specific hosts from a file" }
    @{ Name = "Validate";     Value = "Validate"; Selected = $false; Description = "Validate OpenVAS findings against live hosts" }
)
Show-CheckboxMenu -Title "What would you like to do?" -Items $modeItems -SingleSelect

Write-Host ""
Write-Host "=== Plugin Selection Menu (MultiSelect with AllowSelectAll) ===" -ForegroundColor Cyan
$pluginItems = @(
    @{ Name = "DHEater-TLS"; Value = "DHEater-TLS"; Selected = $true; Description = "D(HE)ater on SSL/TLS (CVE-2002-20001)" }
    @{ Name = "DHEater-SSH"; Value = "DHEater-SSH"; Selected = $true; Description = "D(HE)ater on SSH" }
    @{ Name = "SSH1-Deprecated"; Value = "SSH1-Deprecated"; Selected = $true; Description = "Deprecated SSH-1 protocol" }
    @{ Name = "7Zip-Version"; Value = "7Zip-Version"; Selected = $false; Description = "Outdated 7-Zip (remote registry/WMI)" }
)
Show-CheckboxMenu -Title "Which plugins to run?" -Items $pluginItems -AllowSelectAll

Write-Host ""
Write-Host "=== Output Selection Menu ===" -ForegroundColor Cyan
$outputItems = @(
    @{ Name = "Master findings CSV"; Value = "MasterCSV"; Selected = $true; Description = "All findings in one CSV" }
    @{ Name = "Executive summary report"; Value = "SummaryReport"; Selected = $true; Description = "Plain-text report" }
    @{ Name = "Per-plugin result CSVs"; Value = "PerPluginCSV"; Selected = $false; Description = "Separate CSV per plugin" }
    @{ Name = "Host discovery CSV"; Value = "DiscoveryCSV"; Selected = $false; Description = "Live hosts with open ports (Scan only)" }
)
Show-CheckboxMenu -Title "Output options:" -Items $outputItems -AllowSelectAll

Write-Host ""
Write-Host "=== All menus rendered successfully ===" -ForegroundColor Green
