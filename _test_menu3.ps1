# Test $input inside a function (how Show-CheckboxMenu uses it)
$ErrorActionPreference = 'Continue'

function Test-InputVar {
    # This mimics what Show-CheckboxMenu does
    $input = Read-Host "Enter something"
    Write-Host "Raw `$input value: '$input'" -ForegroundColor Yellow

    if ([string]::IsNullOrWhiteSpace($input)) {
        Write-Host "IsNullOrWhiteSpace returned TRUE" -ForegroundColor Red
    } else {
        Write-Host "IsNullOrWhiteSpace returned FALSE" -ForegroundColor Green
    }

    try {
        $upper = $input.Trim().ToUpper()
        Write-Host ".Trim().ToUpper() = '$upper'" -ForegroundColor Green
    } catch {
        Write-Host ".Trim().ToUpper() FAILED: $_" -ForegroundColor Red
    }
}

Write-Host "=== Test: `$input inside a function ===" -ForegroundColor Cyan
Write-Host "(Providing '2' via stdin)" -ForegroundColor DarkGray
Test-InputVar
