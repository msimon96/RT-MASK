# RT-MASK: Red Team Mask for IPv4 to IPv6 Obfuscation

RT-MASK is a Python script that converts IPv4 addresses to IPv6 addresses for the purpose of IPv4 obfuscation.

## Usage

### Prerequisites

- Python 3.x (Tested on Python 3.6 and above)
- Bash (Tested on version 5.2.15(1)-release (x86_64-pc-linux-gnu)
- PowerShell (5.1+)

### Running the Script

#### Downloading the scripts

    [![asciicast](https://asciinema.org/a/6wasqWBEOx6gzWKfkqYffC3lc.svg)](https://asciinema.org/a/6wasqWBEOx6gzWKfkqYffC3lc)
    ```bash
    git clone https://github.com/msimon96/RT-MASK.git && cd RT-MASK
    ```

#### Python Version


1. Run the Python script:
    
    
    ```bash
    python RT-MASK.py [IPv4_ADDRESS]
    ```

    Replace `[IPv4_ADDRESS]` with the IPv4 address you want to convert.

    Example:

    ```bash
    python RT-MASK.py 192.168.1.1
    ```

    If no IPv4 address is provided as a command-line argument, the script will prompt you to enter one.

    To exit the script, type 'exit' when prompted.

2. For help and usage information:

    ```bash
    python RT-MASK.py -h
    ```

#### Bash Version


1. Run the Bash script:


    [![asciicast](https://asciinema.org/a/RUYQ94zTOg6fXSroPzphnWVfh.svg)](https://asciinema.org/a/RUYQ94zTOg6fXSroPzphnWVfh)
    ```bash
    bash RT-MASK.sh [IPv4_ADDRESS]
    ```

    Replace `[IPv4_ADDRESS]` with the IPv4 address you want to convert.

    Example:

    ```bash
    bash RT-MASK.sh 192.168.1.1
    ```

    If no IPv4 address is provided as a command-line argument, the script will prompt you to enter one.

    To exit the script, type 'exit' when prompted.

2. For help and usage information:

    ```bash
    bash RT-MASK.sh -h
    ```

#### PowerShell Version


1. Run the PowerShell script:

    ```powershell
    .\RT-MASK.ps1 [IPv4_ADDRESS]
    ```

    Replace `[IPv4_ADDRESS]` with the IPv4 address you want to convert.

    Example:

    ```powershell
    .\RT-MASK.ps1 192.168.1.1
    ```

    If no IPv4 address is provided as a command-line argument, the script will prompt you to enter one.

    To exit the script, type 'exit' when prompted.

2. For help and usage information:

    ```powershell
    .\RT-MASK.ps1 -h
    ```

## Notes

- The script uses ANSI escape codes for terminal colors. If you encounter any issues with colors, consider running the script in a terminal that supports ANSI escape codes.


