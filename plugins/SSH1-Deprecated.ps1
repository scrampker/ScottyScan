# SSH1-Deprecated.ps1 - Deprecated SSH-1 Protocol Detection
# Tests for CVE-2001-0361 / CVE-2001-0572

Register-Validator @{
    Name        = "SSH1-Deprecated"
    Description = "Deprecated SSH-1 protocol detection"
    Category    = "Protocol"
    NVTPattern  = "Deprecated SSH-1 Protocol"
    Priority    = 10
    ScanPorts   = @(22, 1022, 2222)
    TestBlock   = {
        param($Context)
        $ip   = $Context.IP
        $port = [int]$Context.Port
        $tout = $Context.TimeoutMs

        if (-not (Test-TCPConnect -IP $ip -Port $port -TimeoutMs $tout)) {
            return @{
                Result = "Unreachable"
                Detail = "Port $port not responding (service may have been removed)"
            }
        }

        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $ar = $client.BeginConnect($ip, $port, $null, $null)
            $waited = $ar.AsyncWaitHandle.WaitOne($tout, $false)
            if (-not $waited) {
                $client.Close()
                return @{ Result = "Unreachable"; Detail = "Connection timed out" }
            }
            $client.EndConnect($ar)
            $stream = $client.GetStream()
            $stream.ReadTimeout = $tout
            $buf = [byte[]]::new(1024)
            $n = $stream.Read($buf, 0, $buf.Length)
            $client.Close()
            $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim()
        } catch {
            try { $client.Close() } catch {}
            return @{ Result = "Error"; Detail = "Failed to read SSH banner: $_" }
        }

        if ($banner -match '^SSH-1\.(5|99)') {
            return @{
                Result = "Vulnerable"
                Detail = "SSH-1 protocol detected. Banner: $banner"
            }
        } elseif ($banner -match '^SSH-2\.0') {
            return @{
                Result = "Remediated"
                Detail = "SSH-2 only. Banner: $banner"
            }
        } else {
            return @{
                Result = "Inconclusive"
                Detail = "Unexpected banner: $banner"
            }
        }
    }
}
