#!/usr/bin/env python3

import ipaddress
import socket
import dns.resolver
import whois
import requests
import json
from dataclasses import dataclass
from typing import Optional, List, Dict, Union
from pathlib import Path
import logging
import qrcode
from datetime import datetime

@dataclass
class GeoLocation:
    country: str
    city: str
    latitude: float
    longitude: float
    timezone: str

@dataclass
class WhoisInfo:
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    name_servers: List[str]
    status: List[str]

@dataclass
class NetworkInfo:
    is_reachable: bool
    latency_ms: Optional[float]
    reverse_dns: Optional[str]
    open_ports: List[int]

@dataclass
class IPConversionResult:
    ipv4: str
    ipv6: str
    url_nossl: str
    url_ssl: str
    domain: Optional[str] = None
    geolocation: Optional[GeoLocation] = None
    whois_info: Optional[WhoisInfo] = None
    network_info: Optional[NetworkInfo] = None
    qr_code_path: Optional[str] = None

class IPConverter:
    def __init__(self, output_dir: Optional[str] = None):
        self.logger = self._setup_logging()
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _setup_logging() -> logging.Logger:
        logger = logging.getLogger('RT-MASK')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain name to IPv4 address."""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return str(answers[0])
        except Exception as e:
            self.logger.error(f"Failed to resolve domain {domain}: {str(e)}")
            return None

    def get_geolocation(self, ip: str) -> Optional[GeoLocation]:
        """Get geolocation information for an IP address."""
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                data = response.json()
                return GeoLocation(
                    country=data.get('country_name', 'Unknown'),
                    city=data.get('city', 'Unknown'),
                    latitude=float(data.get('latitude', 0)),
                    longitude=float(data.get('longitude', 0)),
                    timezone=data.get('timezone', 'Unknown')
                )
        except Exception as e:
            self.logger.error(f"Failed to get geolocation for {ip}: {str(e)}")
        return None

    def get_whois_info(self, domain_or_ip: str) -> Optional[WhoisInfo]:
        """Get WHOIS information for a domain or IP."""
        try:
            w = whois.whois(domain_or_ip)
            return WhoisInfo(
                registrar=w.registrar,
                creation_date=str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                expiration_date=str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
                name_servers=w.name_servers if w.name_servers else [],
                status=w.status if w.status else []
            )
        except Exception as e:
            self.logger.error(f"Failed to get WHOIS info for {domain_or_ip}: {str(e)}")
            return None

    def check_network_info(self, ip: str) -> NetworkInfo:
        """Get basic network information about an IP."""
        import platform
        import subprocess
        from socket import gethostbyaddr
        
        # Check if host is reachable
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        is_reachable = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        
        # Get latency if reachable
        latency_ms = None
        if is_reachable:
            try:
                output = subprocess.check_output(['ping', param, '1', ip])
                if platform.system().lower() == 'windows':
                    latency_ms = float(output.decode().split('Average = ')[-1].split('ms')[0])
                else:
                    latency_ms = float(output.decode().split('time=')[-1].split(' ms')[0])
            except:
                pass

        # Try reverse DNS lookup
        try:
            reverse_dns = gethostbyaddr(ip)[0]
        except:
            reverse_dns = None

        return NetworkInfo(
            is_reachable=is_reachable,
            latency_ms=latency_ms,
            reverse_dns=reverse_dns,
            open_ports=[]  # Could implement basic port scanning here
        )

    def generate_qr_code(self, url: str, ip: str) -> str:
        """Generate QR code for a URL."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        qr_path = self.output_dir / f"qr_{ip.replace('.', '_')}.png"
        img.save(qr_path)
        return str(qr_path)

    def ipv4_to_ipv6(self, ipv4: str) -> str:
        """Convert IPv4 to IPv6 address."""
        try:
            ipv4_obj = ipaddress.IPv4Address(ipv4)
            ipv6_hex = format(int(ipv4_obj), '032x')
            return f"::ffff:{ipv6_hex[0:4]}:{ipv6_hex[4:8]}"
        except Exception as e:
            self.logger.error(f"Failed to convert {ipv4} to IPv6: {str(e)}")
            raise

    def process_ip(self, ip_or_domain: str, generate_qr: bool = False) -> Optional[IPConversionResult]:
        """Process an IP address or domain name with all available information."""
        try:
            # Check if input is a domain
            ipv4 = ip_or_domain
            domain = None
            if not self._is_ip(ip_or_domain):
                domain = ip_or_domain
                resolved_ip = self.resolve_domain(domain)
                if not resolved_ip:
                    return None
                ipv4 = resolved_ip

            # Convert to IPv6
            ipv6 = self.ipv4_to_ipv6(ipv4)
            
            # Generate URLs
            url_nossl = f"http://[{ipv6}]"
            url_ssl = f"https://[{ipv6}]"

            # Generate QR code if requested
            qr_code_path = None
            if generate_qr:
                qr_code_path = self.generate_qr_code(url_ssl, ipv4)

            # Gather additional information
            result = IPConversionResult(
                ipv4=ipv4,
                ipv6=ipv6,
                url_nossl=url_nossl,
                url_ssl=url_ssl,
                domain=domain,
                geolocation=self.get_geolocation(ipv4),
                whois_info=self.get_whois_info(domain or ipv4),
                network_info=self.check_network_info(ipv4),
                qr_code_path=qr_code_path
            )

            return result

        except Exception as e:
            self.logger.error(f"Failed to process {ip_or_domain}: {str(e)}")
            return None

    @staticmethod
    def _is_ip(addr: str) -> bool:
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

    def process_cidr(self, cidr: str, generate_qr: bool = False) -> List[IPConversionResult]:
        """Process all IPs in a CIDR range."""
        results = []
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            for ip in network.hosts():
                result = self.process_ip(str(ip), generate_qr)
                if result:
                    results.append(result)
        except Exception as e:
            self.logger.error(f"Failed to process CIDR {cidr}: {str(e)}")
        return results

    def to_dict(self, result: IPConversionResult) -> Dict:
        """Convert IPConversionResult to dictionary."""
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
            'whois_info': {
                'registrar': result.whois_info.registrar,
                'creation_date': result.whois_info.creation_date,
                'expiration_date': result.whois_info.expiration_date,
                'name_servers': result.whois_info.name_servers,
                'status': result.whois_info.status
            } if result.whois_info else None,
            'network_info': {
                'is_reachable': result.network_info.is_reachable,
                'latency_ms': result.network_info.latency_ms,
                'reverse_dns': result.network_info.reverse_dns,
                'open_ports': result.network_info.open_ports
            } if result.network_info else None,
            'qr_code_path': result.qr_code_path
        }
