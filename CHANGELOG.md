# Changelog

All notable changes to RT-MASK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2023-12-14

### Added
- Windows API integration in PowerShell script:
  - Direct system calls for network operations
  - Native DNS resolution using dnsapi.dll
  - ICMP operations through iphlpapi.dll
  - Enhanced stealth capabilities

### Changed
- PowerShell network operations now use native Windows APIs instead of cmdlets
- Improved performance in PowerShell script through direct API access
- Updated documentation to reflect Windows API usage

### Security
- Reduced detection footprint in PowerShell script
- Eliminated external process creation for network operations
- More discreet network operations using system calls

## [2.0.0] - 2023-12-14

### Added
- Domain name resolution support in both PowerShell and Bash scripts
- Geolocation information using IP-API
- WHOIS lookup functionality
- Network information (ping and reverse DNS)
- Multiple output formats (JSON, HTML, CSV)
- Cross-platform support improvements
- Comprehensive error handling
- Dependency checks in Bash script
- Interactive mode in both scripts
- Example files for testing
- Contributing guidelines
- Improved documentation

### Changed
- Improved ASCII art banner
- Better code organization
- Enhanced error messages
- Updated command-line parameters
- Improved cross-platform compatibility

### Fixed
- Domain resolution in PowerShell script
- WHOIS parsing issues
- Output formatting inconsistencies
- Error handling in network requests

## [1.0.0] - 2023-12-01

### Added
- Initial release
- Basic IPv4 to IPv6 conversion
- CIDR range support
- File input/output
- PowerShell and Bash implementations
