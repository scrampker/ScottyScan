# DHEater-SSH.ps1 - D(HE)ater vulnerability validator for SSH services
# Tests for CVE-2002-20001 / CVE-2022-40735 / CVE-2024-41996

Register-Validator @{
    Name        = "DHEater-SSH"
    Description = "D(HE)ater DoS on SSH key exchange"
    Category    = "Cryptography"
    NVTPattern  = "Diffie-Hellman Ephemeral.*SSH|D\(HE\)ater.*SSH"
    Priority    = 10
    ScanPorts   = @(22, 1022, 2222)
    TestBlock   = {
        param($Context)
        $ip   = $Context.IP
        $port = [int]$Context.Port
        $tout = $Context.TimeoutMs

        if (-not (Test-TCPConnect -IP $ip -Port $port -TimeoutMs $tout)) {
            return @{ Result = "Unreachable"; Detail = "Port $port not responding" }
        }

        $kexInfo = Get-SSHKexAlgorithms -IP $ip -Port $port -TimeoutMs $tout
        if ($null -eq $kexInfo) {
            return @{ Result = "Error"; Detail = "Failed to parse SSH KEX_INIT on port $port" }
        }

        $dheAlgs = $kexInfo.KexAlgorithms | Where-Object { $_ -match '^diffie-hellman-' }
        if ($dheAlgs.Count -gt 0) {
            return @{
                Result = "Vulnerable"
                Detail = "$($dheAlgs.Count) DHE kex: $($dheAlgs -join '; ')"
            }
        }

        $safeAlgs = $kexInfo.KexAlgorithms | Where-Object { $_ -match 'ecdh|curve25519|sntrup' }
        return @{
            Result = "Remediated"
            Detail = "0 DHE kex. $($safeAlgs.Count) safe ECDH/hybrid algorithms. Banner: $($kexInfo.Banner)"
        }
    }
}
