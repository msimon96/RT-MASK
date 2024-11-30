#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from typing import List, Optional
from rtmask.core.ip_converter import IPConverter, IPConversionResult
from rtmask.utils.output_formatter import OutputFormatter

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='RT-MASK: Red Team Mask for IPv4 to IPv6 Obfuscation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -i 192.168.1.1
  %(prog)s -d example.com
  %(prog)s -c 192.168.1.0/24
  %(prog)s -f input.txt
  %(prog)s -i 192.168.1.1 --format json
  %(prog)s -i 192.168.1.1 --qr
  %(prog)s -i 192.168.1.1 --whois --geo
        '''
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-i', '--ip', help='Single IPv4 address to convert')
    input_group.add_argument('-d', '--domain', help='Domain name to resolve and convert')
    input_group.add_argument('-c', '--cidr', help='CIDR notation (e.g., 192.168.1.0/24)')
    input_group.add_argument('-f', '--file', help='File containing IPv4 addresses or CIDR ranges')

    parser.add_argument('-o', '--output', help='Output file (format determined by extension)')
    parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], 
                      default='text', help='Output format')
    parser.add_argument('--output-dir', help='Directory for output files')
    parser.add_argument('--qr', action='store_true', help='Generate QR codes for URLs')
    parser.add_argument('--whois', action='store_true', help='Include WHOIS information')
    parser.add_argument('--geo', action='store_true', help='Include geolocation information')
    parser.add_argument('--network', action='store_true', help='Include network information')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner display')
    
    return parser.parse_args()

def generate_banner() -> str:
    return """
    ######  #######       #     #    #     #####  #    # 
    #     #    #          ##   ##   # #   #     # #   #  
    #     #    #          # # # #  #   #  #       #  #   
    ######     #    ##### #  #  # #     #  #####  ###    
    #   #      #          #     # #######       # #  #   
    #    #     #          #     # #     # #     # #   #  
    #     #    #          #     # #     #  #####  #    # 
    """

def process_input(converter: IPConverter, args: argparse.Namespace) -> List[IPConversionResult]:
    results = []
    
    if args.ip:
        result = converter.process_ip(args.ip, args.qr)
        if result:
            results.append(result)
    
    elif args.domain:
        result = converter.process_ip(args.domain, args.qr)
        if result:
            results.append(result)
    
    elif args.cidr:
        results.extend(converter.process_cidr(args.cidr, args.qr))
    
    elif args.file:
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if '/' in line:  # CIDR notation
                    results.extend(converter.process_cidr(line, args.qr))
                else:
                    result = converter.process_ip(line, args.qr)
                    if result:
                        results.append(result)
    
    else:  # Interactive mode
        while True:
            try:
                user_input = input("\033[93mEnter an IPv4 address, domain, or CIDR (or 'exit' to quit):\033[0m ")
                if user_input.lower() == 'exit':
                    break
                    
                if '/' in user_input:  # CIDR notation
                    results.extend(converter.process_cidr(user_input, args.qr))
                else:
                    result = converter.process_ip(user_input, args.qr)
                    if result:
                        results.append(result)
                        
            except KeyboardInterrupt:
                print("\nExiting...")
                break
                
            except Exception as e:
                print(f"\033[91mError: {str(e)}\033[0m")
    
    return results

def main():
    args = parse_args()
    
    # Show banner unless disabled
    if not args.no_banner:
        print(generate_banner())
    
    # Initialize converter and formatter
    output_dir = args.output_dir if args.output_dir else None
    converter = IPConverter(output_dir)
    formatter = OutputFormatter(output_dir)
    
    # Process input and get results
    results = process_input(converter, args)
    
    if not results:
        print("\033[91mNo valid results to display.\033[0m")
        return
    
    # Handle output based on format
    if args.format == 'text' and not args.output:
        for result in results:
            formatter.print_result(result)
    
    elif args.output or args.format != 'text':
        output_file = args.output if args.output else f"rtmask_results.{args.format}"
        
        if args.format == 'json' or output_file.endswith('.json'):
            formatter.save_json(results, output_file)
        
        elif args.format == 'html' or output_file.endswith('.html'):
            formatter.save_html(results, output_file)
        
        elif args.format == 'csv' or output_file.endswith('.csv'):
            formatter.save_csv(results, output_file)
        
        else:
            print(f"\033[91mUnsupported output format: {args.format}\033[0m")
            return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\033[91mError: {str(e)}\033[0m")
        sys.exit(1)
