# Test $input variable collision directly
$ErrorActionPreference = 'Stop'

Write-Host "=== Test: Does `$input assignment work in PS 5.1? ===" -ForegroundColor Cyan

# Simulate what Show-CheckboxMenu does
$input = "test value"
Write-Host "Assigned `$input = 'test value'"
Write-Host "Reading `$input back: '$input'" -ForegroundColor Yellow

if ([string]::IsNullOrWhiteSpace($input)) {
    Write-Host "PROBLEM: `$input is empty/whitespace despite assignment!" -ForegroundColor Red
} else {
    Write-Host "OK: `$input retained its value" -ForegroundColor Green
}

# Now test .Trim() on it
Write-Host ""
Write-Host "=== Test: Can we call .Trim().ToUpper() on `$input? ===" -ForegroundColor Cyan
try {
    $inputUpper = $input.Trim().ToUpper()
    Write-Host "OK: .Trim().ToUpper() = '$inputUpper'" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# Test with a number string like the menu would get
Write-Host ""
Write-Host "=== Test: Numeric toggle parsing ===" -ForegroundColor Cyan
$input = "2"
$inputUpper = $input.Trim().ToUpper()
$nums = $inputUpper -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
Write-Host "Input: '2', Parsed nums: $($nums -join ', ')" -ForegroundColor Yellow
if ($nums.Count -eq 1 -and $nums[0] -eq "2") {
    Write-Host "OK: Numeric parsing works" -ForegroundColor Green
} else {
    Write-Host "PROBLEM: Expected '2', got: '$($nums -join ', ')' (count=$($nums.Count))" -ForegroundColor Red
}
