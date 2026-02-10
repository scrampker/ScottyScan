# Test the Show-CheckboxMenu function with simulated input
$ErrorActionPreference = 'Continue'

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

    $cursorPos = 0

    while ($true) {
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
        $prompt = if ($SingleSelect) { "  Choice" } else { "  Toggle (#), A=All, N=None, Enter=Done" }
        $input = Read-Host $prompt

        if ([string]::IsNullOrWhiteSpace($input)) {
            break
        }

        $inputUpper = $input.Trim().ToUpper()

        if ($inputUpper -eq 'A' -and $AllowSelectAll -and -not $SingleSelect) {
            foreach ($s in $selections) { $s.Selected = $true }
            continue
        }

        if ($inputUpper -eq 'N' -and $AllowSelectAll -and -not $SingleSelect) {
            foreach ($s in $selections) { $s.Selected = $false }
            continue
        }

        $nums = $inputUpper -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
        foreach ($n in $nums) {
            $idx = [int]$n - 1
            if ($idx -ge 0 -and $idx -lt $selections.Count) {
                if ($SingleSelect) {
                    foreach ($s in $selections) { $s.Selected = $false }
                    $selections[$idx].Selected = $true
                } else {
                    $selections[$idx].Selected = -not $selections[$idx].Selected
                }
            }
        }
    }

    return ($selections | Where-Object { $_.Selected } | ForEach-Object { $_.Value })
}

# Test: Simulate pressing "2" then Enter (via piped input)
Write-Host "=== Testing Show-CheckboxMenu (SingleSelect) ===" -ForegroundColor Cyan
Write-Host "(Will simulate input: '2' then empty line to confirm)" -ForegroundColor DarkGray

$modeItems = @(
    @{ Name = "Network Scan"; Value = "Scan"; Selected = $true; Description = "Discover hosts on CIDRs" }
    @{ Name = "List Scan";    Value = "List"; Selected = $false; Description = "Scan hosts from a file" }
    @{ Name = "Validate";     Value = "Validate"; Selected = $false; Description = "Validate OpenVAS findings" }
)

# We can't truly simulate interactive input in a non-interactive session,
# so let's just test that the function renders without errors
# by providing input via stdin
$result = "2", "" | ForEach-Object { $_ } | & {
    $inputLines = @($input)
    $lineIdx = 0

    # Override Read-Host for testing
    function Read-Host {
        param([string]$Prompt)
        if ($script:lineIdx -lt $script:inputLines.Count) {
            $val = $script:inputLines[$script:lineIdx]
            $script:lineIdx++
            Write-Host "$Prompt : $val" -ForegroundColor DarkCyan
            return $val
        }
        return ""
    }

    Show-CheckboxMenu -Title "What would you like to do?" -Items $modeItems -SingleSelect
}

Write-Host ""
Write-Host "Result: $result" -ForegroundColor Green
