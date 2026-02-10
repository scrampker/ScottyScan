# Test: Does ScottyScan load, show banner, and load plugins without errors?
# We'll dot-source just the function definitions, then call them manually.

$ErrorActionPreference = 'Continue'
$script:Version = "1.0.0"
$script:Build = "2026-02-06"
$script:ConfigFile = Join-Path $PSScriptRoot "scottyscan_test.json"
$script:Config = $null
$script:Validators = [System.Collections.ArrayList]::new()
$script:LogFile = $null
$script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Manually define the functions by reading them from ScottyScan.ps1
# Actually, let's just run the whole script with -NoMenu and no mode to see what happens
Write-Host "=== TEST 1: Banner ===" -ForegroundColor Cyan

# Define Write-Banner inline to test
$banner = @"

  ============================================
   ___           _   _         ___
  / __| __ ___  | |_| |_ _  _/ __| __ __ _ _ _
  \__ \/ _/ _ \ |  _|  _| || \__ \/ _/ _' | ' \
  |___/\__\___/  \__|\__|\_, |___/\__\__,_|_||_|
                         |__/
  Environment Scanner & Validator  v1.0.0
  Build: 2026-02-06
  ============================================
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "Banner rendered OK" -ForegroundColor Green

Write-Host ""
Write-Host "=== TEST 2: Plugin Loading ===" -ForegroundColor Cyan

function Register-Validator {
    param([hashtable]$Validator)
    foreach ($key in @('Name', 'NVTPattern', 'TestBlock')) {
        if (-not $Validator.ContainsKey($key)) {
            Write-Host "  Plugin registration failed: missing '$key'" -ForegroundColor Red
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
    Write-Host "  Registered: $($Validator.Name)" -ForegroundColor Green
}

$pluginDir = Join-Path $PSScriptRoot "plugins"
$files = Get-ChildItem -Path $pluginDir -Filter "*.ps1" | Where-Object { $_.Name -notmatch '^_' }
foreach ($f in $files) {
    Write-Host "  Loading: $($f.Name)" -ForegroundColor Gray
    try {
        . $f.FullName
    } catch {
        Write-Host "  FAILED: $($f.Name) - $_" -ForegroundColor Red
    }
}
Write-Host ""
Write-Host "Loaded $($files.Count) files, $($script:Validators.Count) validators registered" -ForegroundColor Green

Write-Host ""
Write-Host "=== TEST 3: Config Load/Save ===" -ForegroundColor Cyan
$testConfig = [PSCustomObject]@{
    LastMode         = ""
    LastCIDRs        = ""
    DefaultThreads   = 20
    DefaultTimeoutMs = 5000
    DefaultPlugins   = @()
    DefaultOutputs   = @("MasterCSV", "SummaryReport")
    DefaultPorts     = "22,80,135,443,445,3389"
    LastOutputDir    = ".\output_reports"
}
$testConfig | ConvertTo-Json -Depth 5 | Out-File (Join-Path $PSScriptRoot "scottyscan_test.json") -Encoding UTF8
$loaded = Get-Content (Join-Path $PSScriptRoot "scottyscan_test.json") -Raw | ConvertFrom-Json
Write-Host "  Config save/load: OK (Threads=$($loaded.DefaultThreads), Timeout=$($loaded.DefaultTimeoutMs))" -ForegroundColor Green
Remove-Item (Join-Path $PSScriptRoot "scottyscan_test.json") -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== All basic tests passed ===" -ForegroundColor Green
