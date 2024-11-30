# Test suite for RT-MASK PowerShell script

# Counter for tests
$TestsRun = 0
$TestsPassed = 0
$TestsFailed = 0

# Function to run a test
function Run-Test {
    param (
        [string]$TestName,
        [scriptblock]$Command,
        [int]$ExpectedExitCode = 0,
        [string]$ExpectedOutput = ""
    )
    
    Write-Host -NoNewline "Running test: $TestName... "
    $TestsRun++
    
    try {
        # Capture output and any errors
        $output = & $Command 2>&1
        $exitCode = $LASTEXITCODE
        
        # Check exit code if command produced one
        if ($null -ne $exitCode -and $exitCode -ne $ExpectedExitCode) {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "Expected exit code $ExpectedExitCode, got $exitCode"
            $script:TestsFailed++
            return
        }
        
        # Check output if expected output is provided
        if ($ExpectedOutput -and -not ($output | Select-String -Pattern [regex]::Escape($ExpectedOutput))) {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "Expected output containing: $ExpectedOutput"
            Write-Host "Got: $output"
            $script:TestsFailed++
            return
        }
        
        Write-Host "PASSED" -ForegroundColor Green
        $script:TestsPassed++
    }
    catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "Error: $_"
        $script:TestsFailed++
    }
}

# Make sure we're in the right directory
Set-Location -Path (Split-Path -Parent $PSScriptRoot)

# Test help output (this should not error even though we're not showing help in tests)
Run-Test -TestName "Parameter Validation" -Command {
    $null = Get-Command ./RT-MASK.ps1
    $true
}

# Test single IP conversion
Run-Test -TestName "Single IP Conversion" -Command {
    ./RT-MASK.ps1 -IP "192.168.1.1" -Format json
} -ExpectedOutput "::ffff:C0A8:0101"

# Test domain resolution
Run-Test -TestName "Domain Resolution" -Command {
    ./RT-MASK.ps1 -Domain "google.com" -Format json
} -ExpectedOutput '"IPv4":'

# Test CIDR range
Run-Test -TestName "CIDR Range" -Command {
    ./RT-MASK.ps1 -CIDR "192.168.1.0/30" -Format json
} -ExpectedOutput '"IPv4":'

# Test file input with example file
Run-Test -TestName "File Input" -Command {
    ./RT-MASK.ps1 -InputFile "example/sample_networks.txt" -Format json
} -ExpectedOutput '"IPv4":'

# Test WHOIS lookup
Run-Test -TestName "WHOIS Lookup" -Command {
    ./RT-MASK.ps1 -IP "8.8.8.8" -Whois -Format json
} -ExpectedOutput '"WhoisInfo":'

# Test geolocation
Run-Test -TestName "Geolocation" -Command {
    ./RT-MASK.ps1 -IP "8.8.8.8" -Geo -Format json
} -ExpectedOutput '"GeoInfo":'

# Test Windows API functionality
Run-Test -TestName "Windows API - DNS Resolution" -Command {
    $result = ./RT-MASK.ps1 -Domain "google.com" -Format json
    if ($result -match '"IPv4":') {
        return $true
    }
    throw "DNS resolution failed"
} -ExpectedOutput '"IPv4":'

Run-Test -TestName "Windows API - ICMP" -Command {
    $result = ./RT-MASK.ps1 -IP "8.8.8.8" -Format json
    if ($result -match '"NetworkInfo":.*"Reachable": true') {
        return $true
    }
    throw "ICMP test failed"
} -ExpectedOutput '"NetworkInfo":'

Run-Test -TestName "Windows API - Reverse DNS" -Command {
    $result = ./RT-MASK.ps1 -IP "8.8.8.8" -Format json
    if ($result -match '"ReverseDNS":') {
        return $true
    }
    throw "Reverse DNS lookup failed"
} -ExpectedOutput '"ReverseDNS":'

# Print summary
Write-Host "===================="
Write-Host "Test Summary:"
Write-Host "------------------"
Write-Host "Tests Run: $TestsRun"
Write-Host "Tests Passed: $TestsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $TestsFailed" -ForegroundColor Red
Write-Host "===================="

# Exit with failure if any tests failed
if ($TestsFailed -gt 0) {
    exit 1
}
