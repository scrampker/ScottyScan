# DHEater-TLS.ps1 - D(HE)ater vulnerability validator for SSL/TLS services
# Tests for CVE-2002-20001 / CVE-2022-40735 / CVE-2024-41996

Register-Validator @{
    Name        = "DHEater-TLS"
    Description = "D(HE)ater DoS on SSL/TLS (RDP, HTTPS, PostgreSQL)"
    Category    = "Cryptography"
    NVTPattern  = "Diffie-Hellman Ephemeral.*SSL/TLS|D\(HE\)ater.*SSL/TLS"
    Priority    = 10
    ScanPorts   = @(3389, 443, 5432, 636, 8443)
    TestBlock   = {
        param($Context)
        $ip   = $Context.IP
        $port = [int]$Context.Port
        $tout = $Context.TimeoutMs

        # No separate Test-TCPConnect -- first Send-TLSClientHello handles reachability
        $dheCiphers = @(
            @{ Name = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"; Code = [byte[]](0x00, 0x9F) }
            @{ Name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"; Code = [byte[]](0x00, 0x9E) }
            @{ Name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"; Code = [byte[]](0x00, 0x6B) }
            @{ Name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"; Code = [byte[]](0x00, 0x67) }
            @{ Name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";    Code = [byte[]](0x00, 0x39) }
            @{ Name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";    Code = [byte[]](0x00, 0x33) }
        )

        $accepted = @()
        $reachable = $false
        foreach ($cs in $dheCiphers) {
            $result = Send-TLSClientHello -IP $ip -Port $port -CipherCode $cs.Code -TimeoutMs $tout
            if ($null -eq $result) {
                # Connection failed -- if first attempt, port is unreachable; skip rest
                if (-not $reachable) {
                    return @{ Result = "Unreachable"; Detail = "Port $port not responding or TLS handshake failed" }
                }
                # Already got at least one response, this is a transient error -- skip cipher
                continue
            }
            $reachable = $true
            if ($result -eq $true) { $accepted += $cs.Name }
        }

        if ($accepted.Count -gt 0) {
            return @{
                Result = "Vulnerable"
                Detail = "$($accepted.Count) DHE cipher(s) accepted: $($accepted -join '; ')"
            }
        } else {
            return @{ Result = "Remediated"; Detail = "0 DHE ciphers accepted on port $port" }
        }
    }
}
