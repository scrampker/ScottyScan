# _PluginTemplate.ps1 - Template for creating new ScottyScan validators
#
# INSTRUCTIONS:
#   1. Copy this file and rename it (e.g., MyCheck-Version.ps1)
#   2. Fill in the Register-Validator hashtable below
#   3. Drop it in the ScottyScan\plugins\ directory
#   4. It will be auto-loaded on next run
#
# AVAILABLE HELPERS (inside TestBlock):
#   Test-TCPConnect -IP <string> -Port <int> -TimeoutMs <int>
#     -> Returns $true (port open) or $false (closed/timeout)
#
#   Send-TLSClientHello -IP <string> -Port <int> -CipherCode <byte[]> -TimeoutMs <int>
#     -> Returns $true (cipher accepted), $false (rejected), $null (connection error)
#
#   Get-SSHKexAlgorithms -IP <string> -Port <int> -TimeoutMs <int>
#     -> Returns @{ Banner = "SSH-2.0-..."; KexAlgorithms = @("curve25519-sha256", ...) }
#        or $null on connection failure
#
# TESTBLOCK CONTEXT:
#   $Context.IP        - Target IP address
#   $Context.Port      - Target port
#   $Context.Hostname  - Hostname (may be empty)
#   $Context.TimeoutMs - Timeout in milliseconds
#   $Context.Credential - PSCredential (may be $null)
#
# REQUIRED RETURN:
#   @{
#       Result = "Remediated" | "Vulnerable" | "Unreachable" | "Error" | "Inconclusive"
#       Detail = "Human-readable explanation"
#   }

Register-Validator @{
    # --- REQUIRED ---
    Name        = "MyPlugin-Name"          # Unique name, shown in reports
    NVTPattern  = "regex matching nvt_name" # Regex matched against OpenVAS nvt_name column
    TestBlock   = {
        param($Context)
        $ip   = $Context.IP
        $port = [int]$Context.Port
        $tout = $Context.TimeoutMs

        # 1. Check reachability
        if (-not (Test-TCPConnect -IP $ip -Port $port -TimeoutMs $tout)) {
            return @{ Result = "Unreachable"; Detail = "Port $port not responding" }
        }

        # 2. Run your check
        # ... your validation logic here ...

        # 3. Return result
        return @{
            Result = "Vulnerable"  # or "Remediated"
            Detail = "What was found"
        }
    }

    # --- OPTIONAL ---
    Description = "What this plugin checks for"
    Category    = "General"          # Cryptography, Protocol, Software, etc.
    Priority    = 100                # Lower = matched first (for overlapping NVT patterns)
    ScanPorts   = @(443, 8443)       # Ports to scan in -Scan mode (ignored in -Validate)
    PortFilter  = $null              # Regex on port for -Validate NVT matching (e.g., "^(443|8443)$")
    ProtoFilter = $null              # "tcp" or "udp" (or $null for any)
}
