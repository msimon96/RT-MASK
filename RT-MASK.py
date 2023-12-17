import sys
import socket
import binascii

def ipv4_to_ipv6_mapped(ipv4_address):
    ipv4_bytes = socket.inet_aton(ipv4_address)
    ipv6_hex = binascii.hexlify(ipv4_bytes).decode('utf-8')
    ipv6_mapped = f"::ffff:{ipv6_hex}"
    return ipv6_mapped

def print_usage():
    print("Usage: python script_name.py [IPv4_ADDRESS]")
    print("Converts IPv4 addresses to IPv6 for obfuscation.")
    print("\nOptions:")
    print("  IPv4_ADDRESS   Specify the IPv4 address to convert.")
    print("  -h, --help     Show this help message.")
    sys.exit(0)

def process_ip(ipv4_address):
    try:
        socket.inet_aton(ipv4_address)
    except socket.error:
        print("\033[93m" + f"Invalid IPv4 address: {ipv4_address}" + "\033[0m")
        return

    # Call the function to convert IPv4 to IPv6
    ipv6_address = ipv4_to_ipv6_mapped(ipv4_address)

    # Format the output
    ipv6_address_formatted = ipv6_address[0:11] + ":" + ipv6_address[11:]
    url_version_nossl = "\033[92m" + f"https://[{ipv6_address_formatted}]" + "\033[0m"
    url_version_ssl = "\033[92m" + f"https://[{ipv6_address_formatted}]" + "\033[0m"

    print(f"IPv4: \033[93m{ipv4_address}\033[0m")
    print(f"IPv6: \033[93m{ipv6_address_formatted}\033[0m")
    print(f"URL (no SSL): {url_version_nossl}")
    print(f"URL (SSL): {url_version_ssl}")

def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        print_usage()

    if len(sys.argv) > 1:
        # If command-line argument is provided, process it
        process_ip(sys.argv[1])
    else:
        # If no command-line argument, enter loop to get user input
        while True:
            ipv4_address = input("\033[93mEnter an IPv4 address (or 'exit' to quit):\033[0m ")
            if ipv4_address.lower() == 'exit':
                break
            process_ip(ipv4_address)

if __name__ == "__main__":
    main()
