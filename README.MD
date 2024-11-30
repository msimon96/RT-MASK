# RT-MASK: Red Team Mask for IPv4 to IPv6 Obfuscation

RT-MASK is a powerful tool that converts IPv4 addresses to IPv6 addresses for the purpose of IPv4 obfuscation. Version 2.0 introduces many new features including domain name resolution, geolocation information, WHOIS lookup, and multiple output formats.

## Features

- **Multiple Input Methods**:
  - Single IPv4 address
  - Domain name resolution
  - CIDR notation support
  - Batch processing from file
  - Interactive mode

- **Rich Information**:
  - IPv4 to IPv6 conversion
  - URL generation (HTTP/HTTPS)
  - Geolocation information
  - WHOIS lookup
  - Network information (ping, reverse DNS)
  - QR code generation

- **Multiple Output Formats**:
  - Text (console with rich formatting)
  - JSON
  - CSV
  - HTML (modern, responsive design)

- **Cross-Platform Support**:
  - Python implementation (recommended)
  - PowerShell implementation (Windows-optimized using native APIs)
  - Bash implementation

- **Advanced Features**:
  - Direct Windows API calls in PowerShell version for stealth operations
  - Low-level network operations using native system calls
  - Optimized performance through direct API access

## Installation

### Prerequisites

- Python 3.7 or higher
- PowerShell 5.1 or higher (for PowerShell version)
- Bash 4.0 or higher (for Bash version)

#### Bash Version
- Bash 4.0 or higher
- Required utilities:
  - `whois`: WHOIS lookups
  - `curl`: HTTP requests
  - `dig`: DNS resolution
  - `jq`: JSON processing

#### PowerShell Version
- PowerShell 5.1 or higher
- Windows-specific optimizations:
  - Uses native Windows APIs for network operations
  - Direct system calls for DNS resolution
  - ICMP operations through iphlpapi.dll
  - No external command dependencies

### Installing Dependencies

#### macOS
```bash
# Install required utilities for Bash version
brew install whois jq

# Install PowerShell (if needed)
brew install powershell
```

#### Ubuntu/Debian
```bash
# Install required utilities for Bash version
sudo apt-get update
sudo apt-get install whois curl dnsutils jq

# Install PowerShell (if needed)
# Follow instructions at: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux
```

#### Windows
- PowerShell is pre-installed
- For Bash version, use Windows Subsystem for Linux (WSL) and follow Ubuntu/Debian instructions

### Python Version (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/msimon96/RT-MASK.git
cd RT-MASK
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Python Version

```bash
# Single IP conversion
python RT-MASK.py -i 192.168.1.1

# Domain name resolution
python RT-MASK.py -d example.com

# CIDR range
python RT-MASK.py -c 192.168.1.0/24

# Process IPs from file
python RT-MASK.py -f input.txt

# Save results in different formats
python RT-MASK.py -i 192.168.1.1 --format json
python RT-MASK.py -i 192.168.1.1 --format html
python RT-MASK.py -i 192.168.1.1 -o results.csv

# Include additional information
python RT-MASK.py -i 192.168.1.1 --whois --geo --network

# Generate QR codes
python RT-MASK.py -i 192.168.1.1 --qr
```

### Bash Version

```bash
# Make script executable
chmod +x RT-MASK.sh

# Single IP conversion
./RT-MASK.sh -i 192.168.1.1

# Domain name resolution with WHOIS and geolocation
./RT-MASK.sh -d google.com --whois --geo

# CIDR range with JSON output
./RT-MASK.sh -c 192.168.1.0/24 --format json

# Process IPs from file with CSV output
./RT-MASK.sh -f input.txt -o results.csv
```

### PowerShell Version

```powershell
# Single IP conversion
./RT-MASK.ps1 -IP 192.168.1.1

# Domain name resolution with WHOIS and geolocation
./RT-MASK.ps1 -Domain google.com -Whois -Geo

# CIDR range with JSON output
./RT-MASK.ps1 -CIDR 192.168.1.0/24 -Format json

# Process IPs from file with CSV output
./RT-MASK.ps1 -InputFile input.txt -OutputFile results.csv
```

## Command Line Options

### Python Version
```
usage: RT-MASK.py [-h] [-i IP | -d DOMAIN | -c CIDR | -f FILE] [-o OUTPUT]
                  [--format {text,json,csv,html}] [--output-dir OUTPUT_DIR]
                  [--qr] [--whois] [--geo] [--network] [--no-banner]

options:
  -h, --help            show this help message
  -i IP, --ip IP        Single IPv4 address to convert
  -d DOMAIN, --domain DOMAIN
                        Domain name to resolve and convert
  -c CIDR, --cidr CIDR  CIDR notation (e.g., 192.168.1.0/24)
  -f FILE, --file FILE  File containing IPv4 addresses or CIDR ranges
  -o OUTPUT, --output OUTPUT
                        Output file (format determined by extension)
  --format {text,json,csv,html}
                        Output format (default: text)
  --output-dir OUTPUT_DIR
                        Directory for output files
  --qr                  Generate QR codes for URLs
  --whois              Include WHOIS information
  --geo                Include geolocation information
  --network            Include network information
  --no-banner          Disable banner display
```

### Bash Version
```
Usage: RT-MASK.sh [OPTIONS]
Converts IPv4 addresses to IPv6 for obfuscation.

Options:
  -i, --ip IP        Process single IPv4 address
  -d, --domain NAME  Process domain name
  -c, --cidr CIDR    Process CIDR range (e.g., 192.168.1.0/24)
  -f, --file FILE    Input file containing IPv4 addresses, domains, or CIDR ranges
  -o, --output FILE  Output results to file
  --format FORMAT    Output format (text, json, html, csv)
  --whois           Include WHOIS information
  --geo             Include geolocation information
  --no-banner       Don't display the banner
  -h, --help        Show this help message
```

### PowerShell Version
```powershell
Parameters:
  -IP <String>        Process single IPv4 address
  -Domain <String>    Process domain name
  -CIDR <String>      Process CIDR range (e.g., 192.168.1.0/24)
  -InputFile <String> Input file containing IPv4 addresses, domains, or CIDR ranges
  -OutputFile <String> Output results to file
  -Format <String>    Output format (text, json, html, csv)
  -Whois             Include WHOIS information
  -Geo               Include geolocation information
  -NoBanner          Don't display the banner
```

## Output Formats

Both versions support multiple output formats:

1. **Text (Default)**
   - Human-readable console output
   - Color-coded (when supported)
   - Structured for easy reading

2. **JSON**
   - Full structured data
   - Perfect for programmatic processing
   - Includes all collected information

3. **CSV**
   - Tabular format
   - Easy to import into spreadsheets
   - Contains key information in columns

4. **HTML**
   - Modern, responsive design
   - Interactive elements
   - Printer-friendly layout

## API Services Used

The tool uses the following free API services:

1. **IP-API** (http://ip-api.com)
   - Geolocation information
   - Rate limited to 45 requests per minute
   - No API key required

2. **WHOIS**
   - Uses system's WHOIS command
   - Rate limits vary by WHOIS server
   - No API key required

## Examples

1. Basic domain lookup with all information:
```bash
# Bash
./RT-MASK.sh -d github.com --whois --geo --format json

# PowerShell
./RT-MASK.ps1 -Domain github.com -Whois -Geo -Format json
```

2. Process a list of networks and save as HTML:
```bash
# Create input file
echo "192.168.1.0/24
10.0.0.0/8
172.16.0.0/12" > networks.txt

# Bash
./RT-MASK.sh -f networks.txt --format html -o network_map.html

# PowerShell
./RT-MASK.ps1 -InputFile networks.txt -Format html -OutputFile network_map.html
```

3. Interactive mode (no arguments):
```bash
# Bash
./RT-MASK.sh

# PowerShell
./RT-MASK.ps1
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to IP-API for providing free geolocation services
- Thanks to all contributors who have helped improve RT-MASK
- Special thanks to the open-source community for the various tools and libraries used in this project

## Security Notes

- The tool uses public WHOIS servers and IP geolocation services
- No sensitive data is collected or transmitted
- Output files may contain network information - handle them securely
- Consider using the tool through a VPN or proxy for sensitive operations
- PowerShell version uses Windows native APIs for enhanced stealth:
  - Avoids easily monitored PowerShell cmdlets
  - No external process creation
  - Direct system calls for network operations
  - Reduced detection footprint
