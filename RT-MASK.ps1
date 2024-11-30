[CmdletBinding()]
param (
    [Parameter(ParameterSetName = 'SingleIP')]
    [string]$IP,
    
    [Parameter(ParameterSetName = 'Domain')]
    [string]$Domain,
    
    [Parameter(ParameterSetName = 'CIDR')]
    [string]$CIDR,
    
    [Parameter(ParameterSetName = 'File')]
    [string]$InputFile,
    
    [Parameter()]
    [string]$OutputFile,
    
    [Parameter()]
    [switch]$Whois,
    
    [Parameter()]
    [switch]$Geo,
    
    [Parameter()]
    [ValidateSet('text', 'json', 'html', 'csv')]
    [string]$Format = 'text',
    
    [Parameter()]
    [switch]$NoBanner
)

# Check PowerShell version and required modules
$RequiredVersion = [Version]"5.1"
if ($PSVersionTable.PSVersion -lt $RequiredVersion) {
    Write-Error "PowerShell version $RequiredVersion or higher is required."
    exit 1
}

$banner = @"
██████╗ ████████╗      ███╗   ███╗ █████╗ ███████╗██╗  ██╗
██╔══██╗╚══██╔══╝      ████╗ ████║██╔══██╗██╔════╝██║ ██╔╝
██████╔╝   ██║   █████╗██╔████╔██║███████║███████╗█████╔╝ 
██╔══██╗   ██║         ██║╚██╔╝██║██╔══██║╚════██║██╔═██╗ 
██║  ██║   ██║         ██║ ╚═╝ ██║██║  ██║███████║██║  ██╗
╚═╝  ╚═╝   ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                           
     Red Team - Multi-Architecture Subnet Konfigurator     
"@

class IPConversionResult {
    [string]$IPv4
    [string]$IPv6
    [string]$URLNoSSL
    [string]$URLSSL
    [PSCustomObject]$WhoisInfo
    [PSCustomObject]$GeoInfo
    [PSCustomObject]$NetworkInfo

    IPConversionResult([string]$ipv4, [string]$ipv6) {
        $this.IPv4 = $ipv4
        $this.IPv6 = $ipv6
        $this.URLNoSSL = "http://[$ipv6]"
        $this.URLSSL = "https://[$ipv6]"
    }

    [string] ToJson() {
        return $this | ConvertTo-Json -Depth 10
    }

    [string] ToCsv() {
        $props = @(
            $this.IPv4,
            $this.IPv6,
            $this.URLNoSSL,
            $this.URLSSL
        )

        if ($this.WhoisInfo) {
            $props += $this.WhoisInfo.Organization
            $props += $this.WhoisInfo.Country
            $props += $this.WhoisInfo.NetRange
        }

        if ($this.GeoInfo) {
            $props += $this.GeoInfo.City
            $props += $this.GeoInfo.Country
            $props += $this.GeoInfo.Region
            $props += $this.GeoInfo.Timezone
            $props += "$($this.GeoInfo.Lat), $($this.GeoInfo.Lon)"
        }

        if ($this.NetworkInfo) {
            $props += $this.NetworkInfo.Reachable
            $props += $this.NetworkInfo.Latency
            $props += $this.NetworkInfo.ReverseDNS
        }

        return $props -join ","
    }

    [string] ToHtml() {
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RT-MASK Results</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 2em;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 2em;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        table { 
            border-collapse: collapse; 
            width: 100%;
            margin-top: 1em;
        }
        th, td { 
            padding: 12px 8px; 
            text-align: left; 
            border: 1px solid #ddd; 
        }
        th { 
            background-color: #4CAF50; 
            color: white;
        }
        tr:nth-child(even) { 
            background-color: #f9f9f9; 
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 1em;
        }
        .section {
            margin-top: 2em;
            border-top: 1px solid #eee;
            padding-top: 1em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>RT-MASK Results</h1>
        <div class="section">
            <table>
                <tr><th colspan="2">Basic Information</th></tr>
                <tr><td>IPv4</td><td>$($this.IPv4)</td></tr>
                <tr><td>IPv6</td><td>$($this.IPv6)</td></tr>
                <tr><td>URL (no SSL)</td><td>$($this.URLNoSSL)</td></tr>
                <tr><td>URL (SSL)</td><td>$($this.URLSSL)</td></tr>
            </table>
        </div>
"@

        if ($this.WhoisInfo) {
            $html += @"
        <div class="section">
            <table>
                <tr><th colspan="2">WHOIS Information</th></tr>
                <tr><td>Organization</td><td>$($this.WhoisInfo.Organization)</td></tr>
                <tr><td>Country</td><td>$($this.WhoisInfo.Country)</td></tr>
                <tr><td>Net Range</td><td>$($this.WhoisInfo.NetRange)</td></tr>
            </table>
        </div>
"@
        }

        if ($this.GeoInfo) {
            $html += @"
        <div class="section">
            <table>
                <tr><th colspan="2">Geolocation Information</th></tr>
                <tr><td>City</td><td>$($this.GeoInfo.City)</td></tr>
                <tr><td>Country</td><td>$($this.GeoInfo.Country)</td></tr>
                <tr><td>Region</td><td>$($this.GeoInfo.Region)</td></tr>
                <tr><td>Timezone</td><td>$($this.GeoInfo.Timezone)</td></tr>
                <tr><td>Coordinates</td><td>$($this.GeoInfo.Lat), $($this.GeoInfo.Lon)</td></tr>
            </table>
        </div>
"@
        }

        if ($this.NetworkInfo) {
            $html += @"
        <div class="section">
            <table>
                <tr><th colspan="2">Network Information</th></tr>
                <tr><td>Reachable</td><td>$($this.NetworkInfo.Reachable)</td></tr>
                <tr><td>Latency</td><td>$($this.NetworkInfo.Latency) ms</td></tr>
                <tr><td>Reverse DNS</td><td>$($this.NetworkInfo.ReverseDNS)</td></tr>
            </table>
        </div>
"@
        }

        $html += @"
    </div>
</body>
</html>
"@

        return $html
    }
}

# Add Windows API definitions
$TypeDef = @"
using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;

public class NetworkAPI {
    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi)]
    public static extern int getaddrinfo(
        string nodename,
        string servname,
        IntPtr hints,
        out IntPtr res);

    [DllImport("ws2_32.dll")]
    public static extern void freeaddrinfo(IntPtr ai);

    [DllImport("ws2_32.dll", SetLastError = true)]
    public static extern int inet_pton(
        int family,
        string src,
        byte[] dst);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint IcmpCreateFile();

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern bool IcmpCloseHandle(uint handle);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint IcmpSendEcho(
        uint icmpHandle,
        uint ipAddress,
        byte[] requestData,
        ushort requestSize,
        IntPtr requestOptions,
        byte[] replyBuffer,
        uint replySize,
        uint timeout);

    [StructLayout(LayoutKind.Sequential)]
    public class ICMP_ECHO_REPLY {
        public uint Address;
        public uint Status;
        public uint RoundTripTime;
        public ushort DataSize;
        public ushort Reserved;
        public IntPtr DataPtr;
        public byte[] Options = new byte[4];
        public byte[] Data = new byte[250];
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DnsQuery(
        [MarshalAs(UnmanagedType.LPWStr)] string lpstrName,
        short wType,
        int Options,
        IntPtr pExtra,
        ref IntPtr ppQueryResults,
        IntPtr pReserved);

    [DllImport("dnsapi.dll")]
    public static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);

    [StructLayout(LayoutKind.Sequential)]
    public class DNS_RECORD {
        public IntPtr pNext;
        public string pName;
        public short wType;
        public short wDataLength;
        public int flags;
        public int dwTtl;
        public int dwReserved;
        public IntPtr data;
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'NetworkAPI').Type) {
    Add-Type -TypeDefinition $TypeDef
}

function Get-WhoisInformation {
    param (
        [Parameter(Mandatory)]
        [string]$IP
    )
    
    try {
        $whoisServer = "whois.arin.net"
        $port = 43
        $client = New-Object System.Net.Sockets.TcpClient($whoisServer, $port)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)
        
        $writer.WriteLine($IP)
        $writer.Flush()
        
        $response = @()
        while (($line = $reader.ReadLine()) -ne $null) {
            $response += $line
        }
        
        $client.Close()
        
        return [PSCustomObject]@{
            Organization = ($response | Select-String "^Organization:" | ForEach-Object { $_.Line.Split(":")[1].Trim() })[0]
            NetRange = ($response | Select-String "^NetRange:" | ForEach-Object { $_.Line.Split(":")[1].Trim() })[0]
            Country = ($response | Select-String "^Country:" | ForEach-Object { $_.Line.Split(":")[1].Trim() })[0]
            NetName = ($response | Select-String "^NetName:" | ForEach-Object { $_.Line.Split(":")[1].Trim() })[0]
        }
    }
    catch {
        Write-Warning "Failed to get WHOIS information: $_"
        return $null
    }
}

function Get-GeoInformation {
    param (
        [Parameter(Mandatory)]
        [string]$IP
    )
    
    try {
        $maxRetries = 3
        $retryDelay = 1
        
        for ($i = 1; $i -le $maxRetries; $i++) {
            try {
                $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$IP" -TimeoutSec 5
                if ($response.status -eq "success") {
                    return $response
                }
            }
            catch {
                if ($i -eq $maxRetries) {
                    throw
                }
                Start-Sleep -Seconds $retryDelay
            }
        }
        
        return $null
    }
    catch {
        Write-Warning "Failed to get geolocation information: $_"
        return $null
    }
}

function Get-DnsResolution {
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        $queryResults = [IntPtr]::Zero
        $result = [NetworkAPI]::DnsQuery($Name, 1, 0, [IntPtr]::Zero, [ref]$queryResults, [IntPtr]::Zero)
        
        if ($result -eq 0) {
            $record = [System.Runtime.InteropServices.Marshal]::PtrToStructure($queryResults, [Type][NetworkAPI+DNS_RECORD])
            $ipBytes = New-Object byte[] 4
            [System.Runtime.InteropServices.Marshal]::Copy($record.data, $ipBytes, 0, 4)
            $ip = [System.Net.IPAddress]::new($ipBytes)
            [NetworkAPI]::DnsRecordListFree($queryResults, 1)
            return $ip.ToString()
        }
        
        Write-Error "Failed to resolve domain: $Name"
        return $null
    }
    catch {
        Write-Error "Failed to resolve domain: $_"
        return $null
    }
}

function Get-NetworkInformation {
    param (
        [Parameter(Mandatory)]
        [string]$IP
    )

    $reachable = $false
    $latency = "N/A"
    $reverseDNS = "N/A"
    
    try {
        # Convert IP to uint32
        $ipBytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipUint = [System.BitConverter]::ToUInt32($ipBytes, 0)

        # Create ICMP handle
        $icmpHandle = [NetworkAPI]::IcmpCreateFile()
        if ($icmpHandle -eq 0) {
            throw "Failed to create ICMP handle"
        }

        try {
            # Prepare buffers
            $requestData = [System.Text.Encoding]::ASCII.GetBytes("ping")
            $replyBuffer = New-Object byte[] 28
            
            # Send ping
            $result = [NetworkAPI]::IcmpSendEcho(
                $icmpHandle,
                $ipUint,
                $requestData,
                $requestData.Length,
                [IntPtr]::Zero,
                $replyBuffer,
                $replyBuffer.Length,
                1000
            )

            if ($result -ne 0) {
                $reachable = $true
                $reply = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                    [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($replyBuffer, 0),
                    [Type][NetworkAPI+ICMP_ECHO_REPLY]
                )
                $latency = $reply.RoundTripTime
            }
        }
        finally {
            [NetworkAPI]::IcmpCloseHandle($icmpHandle)
        }

        # Get reverse DNS using DnsQuery
        $queryResults = [IntPtr]::Zero
        $arpaName = ($IP -split '\.' | %{[convert]::ToInt32($_)}) -join '.'
        $arpaName = "$arpaName.in-addr.arpa"
        $result = [NetworkAPI]::DnsQuery($arpaName, 12, 0, [IntPtr]::Zero, [ref]$queryResults, [IntPtr]::Zero)
        
        if ($result -eq 0) {
            $record = [System.Runtime.InteropServices.Marshal]::PtrToStructure($queryResults, [Type][NetworkAPI+DNS_RECORD])
            $reverseDNS = $record.pName
            [NetworkAPI]::DnsRecordListFree($queryResults, 1)
        }
    }
    catch {
        Write-Error "Network information error: $_"
    }
    
    return [PSCustomObject]@{
        Reachable = $reachable
        Latency = $latency
        ReverseDNS = $reverseDNS
    }
}

function ConvertTo-IPv6Mapped {
    param (
        [Parameter(Mandatory)]
        [string]$IPv4Address
    )

    try {
        $ipv4_bytes = [BitConverter]::ToString(([IPAddress]$IPv4Address).GetAddressBytes())
        $ipv6_mapped = "::ffff:$($ipv4_bytes.Replace('-', ''))"
        return $ipv6_mapped.Insert(11, ':')
    }
    catch {
        Write-Error "Failed to convert IP address: $_"
        return $null
    }
}

function Test-IPv4Address {
    param (
        [Parameter(Mandatory)]
        [string]$IPv4Address
    )

    try {
        $ip = [IPAddress]::Parse($IPv4Address)
        return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    }
    catch {
        return $false
    }
}

function Get-CIDRAddresses {
    param (
        [Parameter(Mandatory)]
        [string]$CIDRRange
    )

    try {
        $parts = $CIDRRange.Split('/')
        if ($parts.Count -ne 2) {
            throw "Invalid CIDR format"
        }

        $ip = [IPAddress]::Parse($parts[0])
        $maskBits = [int]$parts[1]

        if ($maskBits -lt 0 -or $maskBits -gt 32) {
            throw "Invalid subnet mask length"
        }

        $ipBytes = $ip.GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

        $mask = ([UInt32]0xFFFFFFFF) -shl (32 - $maskBits)
        $network = $ipInt -band $mask
        $broadcast = $network -bor ((-bnot $mask) -band [UInt32]::MaxValue)

        $ips = @()
        for ($i = $network + 1; $i -lt $broadcast; $i++) {
            $bytes = [BitConverter]::GetBytes($i)
            [Array]::Reverse($bytes)
            $ips += [IPAddress]::new($bytes).ToString()
        }

        return $ips
    }
    catch {
        Write-Error "Failed to process CIDR range: $_"
        return @()
    }
}

function Process-IP {
    param (
        [Parameter(Mandatory)]
        [string]$IPv4Address
    )

    if (-not (Test-IPv4Address $IPv4Address)) {
        Write-Error "Invalid IPv4 address: $IPv4Address"
        return $null
    }

    $ipv6 = ConvertTo-IPv6Mapped $IPv4Address
    if ($ipv6) {
        $result = [IPConversionResult]::new($IPv4Address, $ipv6)
        
        if ($Whois) {
            $result.WhoisInfo = Get-WhoisInformation $IPv4Address
        }
        if ($Geo) {
            $result.GeoInfo = Get-GeoInformation $IPv4Address
        }
        $result.NetworkInfo = Get-NetworkInformation $IPv4Address
        
        return $result
    }
    return $null
}

function Format-Result {
    param (
        [Parameter(Mandatory)]
        [IPConversionResult]$Result
    )

    switch ($Format) {
        'json' {
            $Result.ToJson()
        }
        'csv' {
            $Result.ToCsv()
        }
        'html' {
            $Result.ToHtml()
        }
        default {
            $output = [ordered]@{
                IPv4 = $Result.IPv4
                IPv6 = $Result.IPv6
                'URL (no SSL)' = $Result.URLNoSSL
                'URL (SSL)' = $Result.URLSSL
            }
            
            if ($Result.WhoisInfo) {
                $output += @{
                    Organization = $Result.WhoisInfo.Organization
                    NetRange = $Result.WhoisInfo.NetRange
                    Country = $Result.WhoisInfo.Country
                }
            }
            
            if ($Result.GeoInfo) {
                $output += @{
                    City = $Result.GeoInfo.City
                    Region = $Result.GeoInfo.Region
                    Timezone = $Result.GeoInfo.Timezone
                    'Coordinates' = "$($Result.GeoInfo.Lat), $($Result.GeoInfo.Lon)"
                    ISP = $Result.GeoInfo.ISP
                }
            }
            
            if ($Result.NetworkInfo) {
                $output += @{
                    Reachable = if ($Result.NetworkInfo.Reachable) { "✓" } else { "✗" }
                    'Latency (ms)' = $Result.NetworkInfo.Latency
                    'Reverse DNS' = $Result.NetworkInfo.ReverseDNS
                }
            }
            
            foreach ($key in $output.Keys) {
                Write-Host "$key`: " -NoNewline -ForegroundColor Cyan
                Write-Host "$($output[$key])" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }
}

# Main execution logic
$results = @()

if (-not $NoBanner) {
    Write-Host $banner
}

if ($IP) {
    $result = Process-IP $IP
    if ($result) {
        $results += $result
        Format-Result $result
    }
}
elseif ($Domain) {
    try {
        $ip = Get-DnsResolution $Domain
        if ($ip) {
            $result = Process-IP $ip
            if ($result) {
                $results += $result
                Format-Result $result
            }
        }
    }
    catch {
        Write-Error "Failed to resolve domain: $_"
    }
}
elseif ($CIDR) {
    $ips = Get-CIDRAddresses $CIDR
    foreach ($ip in $ips) {
        $result = Process-IP $ip
        if ($result) {
            $results += $result
            Format-Result $result
        }
    }
}
elseif ($InputFile) {
    if (-not (Test-Path $InputFile)) {
        Write-Error "Input file not found: $InputFile"
        exit 1
    }

    Get-Content $InputFile | ForEach-Object {
        $line = $_.Trim()
        if ($line) {
            if ($line -match '/') {
                $ips = Get-CIDRAddresses $line
                foreach ($ip in $ips) {
                    $result = Process-IP $ip
                    if ($result) {
                        $results += $result
                        Format-Result $result
                    }
                }
            }
            elseif ($line -match '\.') {
                try {
                    $ip = Get-DnsResolution $line
                    if ($ip) {
                        $result = Process-IP $ip
                        if ($result) {
                            $results += $result
                            Format-Result $result
                        }
                    }
                }
                catch {
                    Write-Error "Failed to resolve domain: $_"
                }
            }
            else {
                $result = Process-IP $line
                if ($result) {
                    $results += $result
                    Format-Result $result
                }
            }
        }
    }
}
else {
    while ($true) {
        $input = Read-Host "Enter an IPv4 address, CIDR range, or domain name (or 'exit' to quit)"
        if ($input -eq 'exit') {
            break
        }

        if ($input -match '/') {
            $ips = Get-CIDRAddresses $input
            foreach ($ip in $ips) {
                $result = Process-IP $ip
                if ($result) {
                    $results += $result
                    Format-Result $result
                }
            }
        }
        elseif ($input -match '\.') {
            try {
                $ip = Get-DnsResolution $input
                if ($ip) {
                    $result = Process-IP $ip
                    if ($result) {
                        $results += $result
                        Format-Result $result
                    }
                }
            }
            catch {
                Write-Error "Failed to resolve domain: $_"
            }
        }
        else {
            $result = Process-IP $input
            if ($result) {
                $results += $result
                Format-Result $result
            }
        }
    }
}

if ($OutputFile -and $results.Count -gt 0) {
    switch ($Format) {
        'json' {
            $results | ForEach-Object { $_.ToJson() } | Out-File -FilePath $OutputFile
        }
        'csv' {
            $results | ForEach-Object { $_.ToCsv() } | Out-File -FilePath $OutputFile
        }
        'html' {
            $html = "<html><body>"
            foreach ($result in $results) {
                $html += $result.ToHtml()
            }
            $html += "</body></html>"
            $html | Out-File -FilePath $OutputFile
        }
        default {
            $results | Export-Csv -Path $OutputFile -NoTypeInformation
        }
    }
    Write-Host "Results saved to $OutputFile" -ForegroundColor Cyan
}
