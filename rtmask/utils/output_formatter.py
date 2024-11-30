#!/usr/bin/env python3

import json
from typing import List, Union
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.table import Table
from ..core.ip_converter import IPConversionResult

class OutputFormatter:
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()
        
        # Setup Jinja2 environment
        template_dir = Path(__file__).parent.parent / 'templates'
        self.jinja_env = Environment(loader=FileSystemLoader(str(template_dir)))

    def print_result(self, result: IPConversionResult):
        """Print a single result to console with rich formatting."""
        # Create main table
        table = Table(title=f"IP Conversion Result {'(' + result.domain + ')' if result.domain else ''}")
        
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        # Add basic IP information
        table.add_row("IPv4", result.ipv4)
        table.add_row("IPv6", result.ipv6)
        table.add_row("URL (no SSL)", result.url_nossl)
        table.add_row("URL (SSL)", result.url_ssl)
        
        # Add geolocation if available
        if result.geolocation:
            table.add_row("Location", f"{result.geolocation.city}, {result.geolocation.country}")
            table.add_row("Coordinates", f"{result.geolocation.latitude}, {result.geolocation.longitude}")
            table.add_row("Timezone", result.geolocation.timezone)
        
        # Add network info if available
        if result.network_info:
            table.add_row("Reachable", "✅" if result.network_info.is_reachable else "❌")
            if result.network_info.latency_ms:
                table.add_row("Latency", f"{result.network_info.latency_ms:.2f} ms")
            if result.network_info.reverse_dns:
                table.add_row("Reverse DNS", result.network_info.reverse_dns)
        
        # Add WHOIS info if available
        if result.whois_info:
            if result.whois_info.registrar:
                table.add_row("Registrar", result.whois_info.registrar)
            if result.whois_info.creation_date:
                table.add_row("Created", result.whois_info.creation_date)
            if result.whois_info.expiration_date:
                table.add_row("Expires", result.whois_info.expiration_date)
        
        # Add QR code info if available
        if result.qr_code_path:
            table.add_row("QR Code", result.qr_code_path)
        
        self.console.print(table)
        self.console.print()

    def save_json(self, results: Union[IPConversionResult, List[IPConversionResult]], filename: str):
        """Save results to a JSON file."""
        if isinstance(results, IPConversionResult):
            results = [results]
        
        output_file = self.output_dir / filename
        with output_file.open('w') as f:
            json.dump([self._result_to_dict(r) for r in results], f, indent=2)
        
        self.console.print(f"Results saved to [cyan]{output_file}[/cyan]")

    def save_html(self, results: Union[IPConversionResult, List[IPConversionResult]], filename: str):
        """Save results to an HTML file with a modern, responsive design."""
        if isinstance(results, IPConversionResult):
            results = [results]
        
        template = self.jinja_env.get_template('report.html')
        html_content = template.render(
            results=results,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_results=len(results)
        )
        
        output_file = self.output_dir / filename
        output_file.write_text(html_content)
        
        self.console.print(f"HTML report saved to [cyan]{output_file}[/cyan]")

    def save_csv(self, results: Union[IPConversionResult, List[IPConversionResult]], filename: str):
        """Save results to a CSV file."""
        if isinstance(results, IPConversionResult):
            results = [results]
        
        output_file = self.output_dir / filename
        with output_file.open('w') as f:
            # Write header
            f.write("IPv4,IPv6,URL (no SSL),URL (SSL),Domain,Country,City,Latitude,Longitude,Timezone,Reachable,Latency (ms),Reverse DNS\n")
            
            # Write data
            for r in results:
                row = [
                    r.ipv4,
                    r.ipv6,
                    r.url_nossl,
                    r.url_ssl,
                    r.domain or '',
                    r.geolocation.country if r.geolocation else '',
                    r.geolocation.city if r.geolocation else '',
                    str(r.geolocation.latitude) if r.geolocation else '',
                    str(r.geolocation.longitude) if r.geolocation else '',
                    r.geolocation.timezone if r.geolocation else '',
                    str(r.network_info.is_reachable) if r.network_info else '',
                    str(r.network_info.latency_ms) if r.network_info and r.network_info.latency_ms else '',
                    r.network_info.reverse_dns if r.network_info and r.network_info.reverse_dns else ''
                ]
                f.write(','.join(f'"{str(x)}"' for x in row) + '\n')
        
        self.console.print(f"CSV file saved to [cyan]{output_file}[/cyan]")

    @staticmethod
    def _result_to_dict(result: IPConversionResult) -> dict:
        """Convert an IPConversionResult to a dictionary."""
        return {
            'ipv4': result.ipv4,
            'ipv6': result.ipv6,
            'url_nossl': result.url_nossl,
            'url_ssl': result.url_ssl,
            'domain': result.domain,
            'geolocation': {
                'country': result.geolocation.country,
                'city': result.geolocation.city,
                'latitude': result.geolocation.latitude,
                'longitude': result.geolocation.longitude,
                'timezone': result.geolocation.timezone
            } if result.geolocation else None,
            'network_info': {
                'is_reachable': result.network_info.is_reachable,
                'latency_ms': result.network_info.latency_ms,
                'reverse_dns': result.network_info.reverse_dns,
                'open_ports': result.network_info.open_ports
            } if result.network_info else None,
            'whois_info': {
                'registrar': result.whois_info.registrar,
                'creation_date': result.whois_info.creation_date,
                'expiration_date': result.whois_info.expiration_date,
                'name_servers': result.whois_info.name_servers,
                'status': result.whois_info.status
            } if result.whois_info else None,
            'qr_code_path': result.qr_code_path
        }
