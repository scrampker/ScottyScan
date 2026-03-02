<#
Collect-InstalledSoftware-RemoteReg.ps1
Scans a list of Windows hosts via Remote Registry for installed software.
Generates a timestamped CSV in the output directory.

Requirements:
 - Admin rights on targets
 - Remote Registry service running (enable via GPO or services.msc)
 - Targets must allow RPC/SMB traffic (firewall)
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$HostFile,
    [string]$OutputDir = ".\output_reports",
	[string]$LogDir = ".\logs"
)

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

# Prepare output CSV/log
$ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$outCsv  = Join-Path $OutputDir "InstalledSoftware_$ts.csv"
$logFile = Join-Path $LogDir "Collect-InstalledSoftware_$ts.log"

# Load hosts
$hosts = Get-Content -Path $HostFile | Where-Object { $_.Trim() -ne "" }

function Get-InstalledSoftwareFromRemoteRegistry {
    param([string]$ComputerName)

    $baseKeys = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($key in $baseKeys) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $sub = $reg.OpenSubKey($key)
            if ($sub -eq $null) { continue }

            foreach ($name in $sub.GetSubKeyNames()) {
                try {
                    $app = $sub.OpenSubKey($name)
                    $disp = $app.GetValue("DisplayName")
                    if ([string]::IsNullOrWhiteSpace($disp)) { continue }

                    [PSCustomObject]@{
                        ComputerName = $ComputerName
                        Name         = $disp
                        Version      = $app.GetValue("DisplayVersion")
                        Publisher    = $app.GetValue("Publisher")
                        InstallDate  = $app.GetValue("InstallDate")
                        Uninstall    = $app.GetValue("UninstallString")
                        RegistryPath = "HKLM:\$key\$name"
                    }
                }
                catch {
                    "[$ComputerName] Failed reading subkey $name : $_" | Out-File -FilePath $logFile -Append
                }
            }
        }
        catch {
            "[$ComputerName] Failed opening base key $key : $_" | Out-File -FilePath $logFile -Append
        }
    }
}

# Collect from all hosts (stream objects directly)
$allResults = $hosts | ForEach-Object {
    $target = $_
    Write-Output "Scanning $target..." | Tee-Object -FilePath $logFile -Append
    try {
        Get-InstalledSoftwareFromRemoteRegistry -ComputerName $target
    } catch {
        "[$target] ERROR: $_" | Tee-Object -FilePath $logFile -Append
    }
}

# Export results
if ($allResults) {
    $allResults |
        Sort-Object ComputerName, Name |
        Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
    Write-Output "Done. Output CSV: $outCsv"
} else {
    Write-Output "No data collected. See log: $logFile"
}
