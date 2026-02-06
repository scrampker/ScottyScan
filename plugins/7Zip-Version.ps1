# 7Zip-Version.ps1 - 7-Zip version check (remote registry/WMI)
# Covers CVE-2024-11477, CVE-2025-0411, and related 7-Zip CVEs

Register-Validator @{
    Name        = "7Zip-Version"
    Description = "Outdated 7-Zip installations (remote check)"
    Category    = "Software"
    NVTPattern  = "7-Zip.*Vulnerabilit|7-Zip.*Mark-of-the-Web"
    Priority    = 20
    ScanPorts   = @()  # Software check, no port scanning
    TestBlock   = {
        param($Context)
        $ip   = $Context.IP
        $cred = $Context.Credential

        $safeVersion = [version]"24.9.0"
        $installed = $null
        $method = ""

        # Method 1: PSRemoting
        try {
            $sbParams = @{ ComputerName = $ip; ErrorAction = 'Stop' }
            if ($cred) { $sbParams['Credential'] = $cred }
            $remoteResult = Invoke-Command @sbParams -ScriptBlock {
                $paths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                foreach ($p in $paths) {
                    Get-ItemProperty $p -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -match '7-Zip' } |
                        Select-Object DisplayName, DisplayVersion
                }
            }
            if ($remoteResult) {
                $installed = $remoteResult
                $method = "PSRemoting"
            }
        } catch {}

        # Method 2: WMI
        if (-not $installed) {
            try {
                $wmiParams = @{ ComputerName = $ip; Class = 'Win32_Product'; ErrorAction = 'Stop' }
                if ($cred) { $wmiParams['Credential'] = $cred }
                $wmiResult = Get-WmiObject @wmiParams |
                    Where-Object { $_.Name -match '7-Zip' }
                if ($wmiResult) {
                    $installed = $wmiResult | Select-Object `
                        @{N='DisplayName';E={$_.Name}}, @{N='DisplayVersion';E={$_.Version}}
                    $method = "WMI"
                }
            } catch {}
        }

        if (-not $installed) {
            return @{
                Result = "Inconclusive"
                Detail = "Could not remotely query 7-Zip. PSRemoting and WMI both failed."
            }
        }

        $vuln = $false
        foreach ($app in $installed) {
            $verStr = $app.DisplayVersion
            try {
                $parts = $verStr -split '\.'
                if ($parts.Count -eq 2) {
                    $testVer = [version]("{0}.{1}.0" -f $parts[0], $parts[1])
                } else {
                    $testVer = [version]$verStr
                }
                if ($testVer -lt $safeVersion) { $vuln = $true }
            } catch { $vuln = $true }
        }

        $names = ($installed | ForEach-Object {
            "{0} v{1}" -f $_.DisplayName, $_.DisplayVersion
        }) -join '; '

        if ($vuln) {
            return @{
                Result = "Vulnerable"
                Detail = "Outdated via $method -- $names (needs >= $safeVersion)"
            }
        } else {
            return @{
                Result = "Remediated"
                Detail = "Current via $method -- $names"
            }
        }
    }
}
