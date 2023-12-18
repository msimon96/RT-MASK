$banner = @"
######  #######       #     #    #     #####  #    # 
#     #    #          ##   ##   # #   #     # #   #  
#     #    #          # # # #  #   #  #       #  #   
######     #    ##### #  #  # #     #  #####  ###    
#   #      #          #     # #######       # #  #   
#    #     #          #     # #     # #     # #   #  
#     #    #          #     # #     #  #####  #    # 
"@

function ConvertTo-IPv6Mapped {
    param (
        [string]$ipv4_address
    )

    $ipv4_bytes = [BitConverter]::ToString(([IPAddress]$ipv4_address).GetAddressBytes())
    $ipv6_mapped = "::ffff:$ipv4_bytes".Replace("-", "")
    return $ipv6_mapped
}

function Show-Usage {
    Write-Host "Usage: powershell script_name.ps1 [IPv4_ADDRESS]"
    Write-Host "Converts IPv4 addresses to IPv6 for obfuscation."
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  IPv4_ADDRESS   Specify the IPv4 address to convert."
    Write-Host "  -h, --help     Show this help message."
    exit 0
}

function Invoke-IPProcessing {
    param (
        [string]$ipv4_address
    )

    try {
        $ipv4_test = [System.Net.IPAddress]::Parse($ipv4_address)
    } catch {
        Write-Host "Invalid IPv4 address: $ipv4_address" -ForegroundColor Red
        return
    }

    # Call the function to convert IPv4 to IPv6
    $ipv6_address = ConvertTo-IPv6Mapped $ipv4_address

    # Format the output
    $ipv6_address_formatted = "$($ipv6_address.Substring(0, 11)):$($ipv6_address.Substring(11))"
    $url_version_nossl = "https://[$ipv6_address_formatted]"
    $url_version_ssl = "https://[$ipv6_address_formatted]"

    Write-Host "IPv4: $ipv4_address" -ForegroundColor Yellow
    Write-Host "IPv6: $ipv6_address_formatted" -ForegroundColor Yellow
    Write-Host "URL (no SSL): $url_version_nossl" -ForegroundColor Green
    Write-Host "URL (SSL): $url_version_ssl" -ForegroundColor Green
}

if ($args -contains "-h" -or $args -contains "--help") {
    Show-Usage
}

if ($args.Length -gt 0) {
    # If command-line argument is provided, process it
    Process-IP $args[0]
} else {
    # If no command-line argument, enter loop to get user input
    Write-Host $banner # Comment out if you don't want the banner
    while ($true) {
        $ipv4_address = Read-Host "Enter an IPv4 address (or 'exit' to quit):"
        if ($ipv4_address -eq "exit") {
            break
        }
        Invoke-IPProcessing $ipv4_address
    }
}
