#!/bin/bash

banner="
######  #######       #     #    #     #####  #    # 
#     #    #          ##   ##   # #   #     # #   #  
#     #    #          # # # #  #   #  #       #  #   
######     #    ##### #  #  # #     #  #####  ###    
#   #      #          #     # #######       # #  #   
#    #     #          #     # #     # #     # #   #  
#     #    #          #     # #     #  #####  #    # 
"

ipv4_to_ipv6_mapped() {
    local ipv4_address=$1
    IFS='.' read -r -a octets <<< "$ipv4_address"
    ipv6_mapped="::ffff:"
    
    for octet in "${octets[@]}"; do
        hex_octet=$(printf "%02X" "$octet")  # Use "%02X" for uppercase hexadecimal
        ipv6_mapped+="$hex_octet"
    done
    
    echo "$ipv6_mapped"
}

print_usage() {
    echo "Usage: bash script_name.sh [IPv4_ADDRESS]"
    echo "Converts IPv4 addresses to IPv6 for obfuscation."
    echo -e "\nOptions:"
    echo "  IPv4_ADDRESS   Specify the IPv4 address to convert."
    echo "  -h, --help     Show this help message."
    exit 0
}

process_ip() {
    local ipv4_address=$1
    if ! [[ $ipv4_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "Invalid IPv4 address: $ipv4_address"
        return
    fi

    # Call the function to convert IPv4 to IPv6
    ipv6_address=$(ipv4_to_ipv6_mapped "$ipv4_address")

    # Format the output
    ipv6_address_formatted="${ipv6_address:0:11}:${ipv6_address:11}"
    url_version_nossl="https://[${ipv6_address_formatted}]"
    url_version_ssl="https://[${ipv6_address_formatted}]"
    
    # Add a new line
    echo ""

    # Print the results
    echo "IPv4: $ipv4_address"
    echo "IPv6: $ipv6_address_formatted"
    echo "URL (no SSL): $url_version_nossl"
    echo "URL (SSL): $url_version_ssl"

    # Add a new line
    echo ""
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    print_usage
fi

if [ $# -gt 0 ]; then
    # If command-line argument is provided, process it
    process_ip "$1"
else
    # If no command-line argument, enter loop to get user input
    echo "$banner" # Comment this line out if you don't want the banner
    while true; do
        read -r -p $'Enter an IPv4 address (or \'exit\' to quit): ' ipv4_address
        if [[ "$ipv4_address" == "exit" ]]; then
            break
        fi
        process_ip "$ipv4_address"
    done
fi
