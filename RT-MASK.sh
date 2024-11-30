#!/bin/bash

# Default values
INPUT_FILE=""
OUTPUT_FILE=""
SHOW_BANNER=true
IP_ADDRESS=""
DOMAIN_NAME=""
CIDR_RANGE=""
FORMAT="text"
WHOIS=false
GEO=false

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check for required commands
check_dependencies() {
    local missing_deps=()
    
    # List of required commands
    local deps=("whois" "curl" "dig" "jq")
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Error: Missing required dependencies: ${missing_deps[*]}${NC}"
        echo "Please install them using your package manager:"
        echo "For macOS: brew install ${missing_deps[*]}"
        echo "For Ubuntu/Debian: sudo apt-get install ${missing_deps[*]}"
        echo "For CentOS/RHEL: sudo yum install ${missing_deps[*]}"
        exit 1
    fi
}

banner="
██████╗ ████████╗      ███╗   ███╗ █████╗ ███████╗██╗  ██╗
██╔══██╗╚══██╔══╝      ████╗ ████║██╔══██╗██╔════╝██║ ██╔╝
██████╔╝   ██║   █████╗██╔████╔██║███████║███████╗█████╔╝ 
██╔══██╗   ██║         ██║╚██╔╝██║██╔══██║╚════██║██╔═██╗ 
██║  ██║   ██║         ██║ ╚═╝ ██║██║  ██║███████║██║  ██╗
╚═╝  ╚═╝   ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                           
     Red Team - Multi-Architecture Subnet Konfigurator     
"

# Function to print error messages
error() {
    echo -e "${RED}Error: $1${NC}" >&2
}

# Function to print info messages
info() {
    echo -e "${CYAN}$1${NC}"
}

# Function to get WHOIS information
get_whois_info() {
    local ip=$1
    local whois_data
    local whois_info
    
    whois_data=$(whois "$ip" 2>/dev/null) || return 1
    
    # Create JSON output
    whois_info=$(jq -n \
        --arg org "$(echo "$whois_data" | grep -i "^Organization:" | head -n1 | cut -d: -f2- | xargs)" \
        --arg country "$(echo "$whois_data" | grep -i "^Country:" | head -n1 | cut -d: -f2- | xargs)" \
        --arg netrange "$(echo "$whois_data" | grep -i "^NetRange:" | head -n1 | cut -d: -f2- | xargs)" \
        --arg netname "$(echo "$whois_data" | grep -i "^NetName:" | head -n1 | cut -d: -f2- | xargs)" \
        '{
            "organization": $org,
            "country": $country,
            "netrange": $netrange,
            "netname": $netname
        }')
    
    echo "$whois_info"
}

# Function to get geolocation information
get_geo_info() {
    local ip=$1
    local geo_data
    
    # Retry mechanism for API calls
    for i in {1..3}; do
        geo_data=$(curl -s --max-time 5 "http://ip-api.com/json/$ip") || continue
        
        if [[ $geo_data == *"\"status\":\"success\""* ]]; then
            echo "$geo_data"
            return 0
        fi
        
        sleep 1
    done
    
    return 1
}

# Function to get network information
get_network_info() {
    local ip=$1
    local ping_result="N/A"
    local reverse_dns="N/A"
    local reachable="false"
    
    # Try ping with timeout
    if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
        ping_result=$(ping -c 1 -W 2 "$ip" | grep "time=" | cut -d "=" -f4 | xargs)
        reachable="true"
    fi
    
    # Try reverse DNS lookup with timeout
    reverse_dns=$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null || echo "N/A")
    
    # Create JSON output
    jq -n \
        --arg reachable "$reachable" \
        --arg latency "$ping_result" \
        --arg dns "$reverse_dns" \
        '{
            "reachable": $reachable,
            "latency": $latency,
            "reverse_dns": $dns
        }'
}

# Function to resolve domain to IP
resolve_domain() {
    local domain="$1"
    local ip_address
    
    ip_address=$(dig +short "$domain" A | head -n1)
    if [[ -z $ip_address ]]; then
        error "Failed to resolve domain: $domain"
        return 1
    fi
    echo "$ip_address"
}

# Function to validate IPv4 address
validate_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Function to convert IPv4 to IPv6
ipv4_to_ipv6_mapped() {
    local ipv4_address=$1
    IFS='.' read -r -a octets <<< "$ipv4_address"
    local ipv6_mapped="::ffff:"
    
    for octet in "${octets[@]}"; do
        local hex_octet=$(printf "%02X" "$octet")
        ipv6_mapped+="$hex_octet"
    done
    
    # Format with colon after prefix
    echo "${ipv6_mapped:0:11}:${ipv6_mapped:11}"
}

# Function to process a single IP
process_ip() {
    local ipv4_address=$1
    
    if ! validate_ipv4 "$ipv4_address"; then
        error "Invalid IPv4 address: $ipv4_address"
        return 1
    fi

    local ipv6_address
    local whois_data
    local geo_data
    local network_data
    
    ipv6_address=$(ipv4_to_ipv6_mapped "$ipv4_address")
    
    # Prepare base result
    local result=$(jq -n \
        --arg ipv4 "$ipv4_address" \
        --arg ipv6 "$ipv6_address" \
        --arg url_nossl "http://[$ipv6_address]" \
        --arg url_ssl "https://[$ipv6_address]" \
        '{
            "ipv4": $ipv4,
            "ipv6": $ipv6,
            "url_nossl": $url_nossl,
            "url_ssl": $url_ssl
        }')
    
    # Add WHOIS information if requested
    if [[ $WHOIS == true ]]; then
        whois_data=$(get_whois_info "$ipv4_address")
        if [[ -n $whois_data ]]; then
            result=$(echo "$result" | jq --argjson whois "$whois_data" '. + {"whois": $whois}')
        fi
    fi
    
    # Add geolocation information if requested
    if [[ $GEO == true ]]; then
        geo_data=$(get_geo_info "$ipv4_address")
        if [[ -n $geo_data ]]; then
            result=$(echo "$result" | jq --argjson geo "$geo_data" '. + {"geo": $geo}')
        fi
    fi
    
    # Add network information
    network_data=$(get_network_info "$ipv4_address")
    result=$(echo "$result" | jq --argjson network "$network_data" '. + {"network": $network}')
    
    # Format and output the results
    case $FORMAT in
        "json")
            echo "$result" | jq '.'
            ;;
        "html")
            generate_html_output "$result"
            ;;
        "csv")
            generate_csv_output "$result"
            ;;
        *)
            # Text output with colors
            echo -e "\n${CYAN}IPv4:${NC} ${YELLOW}$ipv4_address${NC}"
            echo -e "${CYAN}IPv6:${NC} ${YELLOW}$ipv6_address${NC}"
            echo -e "${CYAN}URL (no SSL):${NC} ${GREEN}http://[$ipv6_address]${NC}"
            echo -e "${CYAN}URL (SSL):${NC} ${GREEN}https://[$ipv6_address]${NC}"
            
            if [[ $WHOIS == true && -n $whois_data ]]; then
                echo -e "\n${CYAN}WHOIS Information:${NC}"
                echo "$whois_data" | jq -r 'to_entries | .[] | "\(.key): \(.value)"' | while read -r line; do
                    key=$(echo "$line" | cut -d: -f1)
                    value=$(echo "$line" | cut -d: -f2-)
                    echo -e "${CYAN}${key^}:${NC}${value}"
                done
            fi
            
            if [[ $GEO == true && -n $geo_data ]]; then
                echo -e "\n${CYAN}Geolocation Information:${NC}"
                echo "$geo_data" | jq -r 'to_entries | .[] | select(.key != "status") | "\(.key): \(.value)"' | while read -r line; do
                    key=$(echo "$line" | cut -d: -f1)
                    value=$(echo "$line" | cut -d: -f2-)
                    echo -e "${CYAN}${key^}:${NC}${value}"
                done
            fi
            
            echo -e "\n${CYAN}Network Information:${NC}"
            echo "$network_data" | jq -r 'to_entries | .[] | "\(.key): \(.value)"' | while read -r line; do
                key=$(echo "$line" | cut -d: -f1)
                value=$(echo "$line" | cut -d: -f2-)
                echo -e "${CYAN}${key^}:${NC}${value}"
            done
            echo
            ;;
    esac
}

# Function to process CIDR range
process_cidr() {
    local cidr=$1
    
    # Extract IP and prefix
    IFS='/' read -r ip prefix <<< "$cidr"
    
    if ! validate_ipv4 "$ip" || [[ ! $prefix =~ ^[0-9]+$ ]] || [ "$prefix" -gt 32 ]; then
        error "Invalid CIDR notation: $cidr"
        return 1
    fi

    # Convert IP to integer
    IFS='.' read -r a b c d <<< "$ip"
    local ip_int=$((a * 256 ** 3 + b * 256 ** 2 + c * 256 + d))
    
    # Calculate network and broadcast addresses
    local mask=$((0xffffffff << (32 - prefix)))
    local network=$((ip_int & mask))
    local broadcast=$((network | ~mask & 0xffffffff))
    
    # Process each IP in range (excluding network and broadcast)
    for ((i = network + 1; i < broadcast; i++)); do
        local new_ip=$(printf "%d.%d.%d.%d" \
            $((i >> 24 & 255)) \
            $((i >> 16 & 255)) \
            $((i >> 8 & 255)) \
            $((i & 255)))
        process_ip "$new_ip"
    done
}

# Function to show usage
print_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]
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

Examples:
  $(basename "$0") -i 192.168.1.1 --whois --geo
  $(basename "$0") -d google.com --format json
  $(basename "$0") -c 192.168.1.0/24 --format html -o results.html
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--ip)
            IP_ADDRESS="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        -c|--cidr)
            CIDR_RANGE="$2"
            shift 2
            ;;
        -f|--file)
            INPUT_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --whois)
            WHOIS=true
            shift
            ;;
        --geo)
            GEO=true
            shift
            ;;
        --no-banner)
            SHOW_BANNER=false
            shift
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            error "Unknown option: $1"
            print_usage
            ;;
    esac
done

# Show banner if enabled
if [[ $SHOW_BANNER == true ]]; then
    echo "$banner"
fi

# Initialize output file if specified
if [[ -n $OUTPUT_FILE ]]; then
    case $FORMAT in
        "csv")
            echo "IPv4,IPv6,URL (no SSL),URL (SSL)" > "$OUTPUT_FILE"
            ;;
    esac
fi

# Process based on input type
if [[ -n $IP_ADDRESS ]]; then
    if [[ -n $OUTPUT_FILE ]]; then
        process_ip "$IP_ADDRESS" >> "$OUTPUT_FILE"
    else
        process_ip "$IP_ADDRESS"
    fi
elif [[ -n $DOMAIN_NAME ]]; then
    ip_address=$(resolve_domain "$DOMAIN_NAME")
    if [[ -n $ip_address ]]; then
        if [[ -n $OUTPUT_FILE ]]; then
            process_ip "$ip_address" >> "$OUTPUT_FILE"
        else
            process_ip "$ip_address"
        fi
    else
        error "Failed to resolve domain: $DOMAIN_NAME"
    fi
elif [[ -n $CIDR_RANGE ]]; then
    if [[ -n $OUTPUT_FILE ]]; then
        process_cidr "$CIDR_RANGE" >> "$OUTPUT_FILE"
    else
        process_cidr "$CIDR_RANGE"
    fi
elif [[ -n $INPUT_FILE ]]; then
    if [[ ! -f $INPUT_FILE ]]; then
        error "Input file not found: $INPUT_FILE"
        exit 1
    fi
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | tr -d '\r\n')
        [[ -z $line || $line =~ ^[[:space:]]*# ]] && continue
        
        if [[ $line =~ / ]]; then
            if [[ -n $OUTPUT_FILE ]]; then
                process_cidr "$line" >> "$OUTPUT_FILE"
            else
                process_cidr "$line"
            fi
        elif [[ $line =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            if [[ -n $OUTPUT_FILE ]]; then
                process_ip "$line" >> "$OUTPUT_FILE"
            else
                process_ip "$line"
            fi
        else
            ip_address=$(resolve_domain "$line")
            if [[ -n $ip_address ]]; then
                if [[ -n $OUTPUT_FILE ]]; then
                    process_ip "$ip_address" >> "$OUTPUT_FILE"
                else
                    process_ip "$ip_address"
                fi
            else
                error "Failed to resolve domain: $line"
            fi
        fi
    done < "$INPUT_FILE"
else
    # Interactive mode
    while true; do
        read -r -p $'Enter an IPv4 address, domain name, or CIDR range (or \'exit\' to quit): ' input
        [[ $input == "exit" ]] && break
        
        if [[ $input =~ / ]]; then
            if [[ -n $OUTPUT_FILE ]]; then
                process_cidr "$input" >> "$OUTPUT_FILE"
            else
                process_cidr "$input"
            fi
        elif [[ $input =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            if [[ -n $OUTPUT_FILE ]]; then
                process_ip "$input" >> "$OUTPUT_FILE"
            else
                process_ip "$input"
            fi
        else
            ip_address=$(resolve_domain "$input")
            if [[ -n $ip_address ]]; then
                if [[ -n $OUTPUT_FILE ]]; then
                    process_ip "$ip_address" >> "$OUTPUT_FILE"
                else
                    process_ip "$ip_address"
                fi
            else
                error "Failed to resolve domain: $input"
            fi
        fi
    done
fi

# Show success message if output file was created
if [[ -n $OUTPUT_FILE && -f $OUTPUT_FILE ]]; then
    info "Results saved to $OUTPUT_FILE"
fi
