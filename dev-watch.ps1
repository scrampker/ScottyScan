<#
.SYNOPSIS
    Dev watcher -- auto-restarts ScottyScan.ps1 when the file is saved.
    Run this in a separate terminal while editing. Ctrl+C to stop.
.USAGE
    powershell -ExecutionPolicy Bypass -File .\dev-watch.ps1
#>

$scriptPath = Join-Path $PSScriptRoot "ScottyScan.ps1"
if (-not (Test-Path $scriptPath)) {
    Write-Host "ScottyScan.ps1 not found in $PSScriptRoot" -ForegroundColor Red
    exit 1
}

# Also watch plugin files
$pluginDir = Join-Path $PSScriptRoot "plugins"

Write-Host ""
Write-Host "  [dev-watch] Watching for changes to ScottyScan.ps1 and plugins/" -ForegroundColor Magenta
Write-Host "  [dev-watch] Press Ctrl+C in this window to stop." -ForegroundColor Magenta
Write-Host ""
Start-Sleep -Milliseconds 1000

while ($true) {
    # Snapshot timestamps before launch
    $lastWrite = (Get-Item $scriptPath).LastWriteTime
    $pluginStamps = @{}
    if (Test-Path $pluginDir) {
        Get-ChildItem $pluginDir -Filter "*.ps1" | ForEach-Object {
            $pluginStamps[$_.FullName] = $_.LastWriteTime
        }
    }

    # Launch ScottyScan as a child process sharing this console.
    # UseShellExecute=$false means it inherits our console handles,
    # so [Console]::ReadKey in the child reads from this terminal.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)

    # Poll for file changes while the process runs
    $changed = $false
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 500
        try {
            # Check main script
            $currentWrite = (Get-Item $scriptPath).LastWriteTime
            if ($currentWrite -ne $lastWrite) {
                $changed = $true
                break
            }
            # Check plugins
            if (Test-Path $pluginDir) {
                $currentPlugins = Get-ChildItem $pluginDir -Filter "*.ps1"
                foreach ($p in $currentPlugins) {
                    if (-not $pluginStamps.ContainsKey($p.FullName) -or
                        $p.LastWriteTime -ne $pluginStamps[$p.FullName]) {
                        $changed = $true
                        break
                    }
                }
                if ($changed) { break }
            }
        } catch {}
    }

    if ($changed -and -not $proc.HasExited) {
        # Kill the running instance
        try {
            $proc.Kill()
            $proc.WaitForExit(2000)
        } catch {}

        # Brief pause for file write to finish (editors sometimes do write-rename)
        Start-Sleep -Milliseconds 400

        # Clear screen and show reload message
        Clear-Host
        Write-Host ""
        Write-Host "  [dev-watch] File changed -- restarting ScottyScan..." -ForegroundColor Magenta
        Write-Host ""
        Start-Sleep -Milliseconds 600
    } elseif (-not $changed) {
        # Process exited on its own (user pressed Esc=Exit, or scan completed)
        # Wait a moment then relaunch
        Write-Host ""
        Write-Host "  [dev-watch] ScottyScan exited. Relaunching in 2s... (Ctrl+C to stop)" -ForegroundColor Magenta
        Start-Sleep -Milliseconds 2000
    }
}
