import ipaddress
import re
import socket
from typing import List, Optional, Tuple

from utils.logger import logger


DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def is_valid_ip(ip: str) -> bool:
    if not IP_RE.match(ip):
        return False
    parts = [int(p) for p in ip.split('.')]
    return all(0 <= p <= 255 for p in parts)


def parse_targets(target_string: str) -> List[str]:
    ips: List[str] = []
    parts = [p.strip() for p in target_string.split(',') if p.strip()]

    for part in parts:
        try:
            if '/' in part:
                network = ipaddress.ip_network(part, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            elif '-' in part:
                start_ip_str, end_suffix = part.split('-', 1)
                start_ip_str = start_ip_str.strip()
                end_suffix = end_suffix.strip()

                if not is_valid_ip(start_ip_str):
                    logger.warning(f"Invalid IP address: {start_ip_str}")
                    continue

                start_ip = ipaddress.ip_address(start_ip_str)

                if '.' in end_suffix and end_suffix.count('.') == 3:
                    if not is_valid_ip(end_suffix):
                        logger.warning(f"Invalid IP address: {end_suffix}")
                        continue
                    end_ip = ipaddress.ip_address(end_suffix)
                else:
                    ip_parts = start_ip_str.split('.')
                    ip_parts[-1] = end_suffix
                    end_ip_str = '.'.join(ip_parts)
                    if not is_valid_ip(end_ip_str):
                        logger.warning(f"Invalid IP range end: {end_suffix}")
                        continue
                    end_ip = ipaddress.ip_address(end_ip_str)

                start_int = int(start_ip)
                end_int = int(end_ip)
                if start_int > end_int:
                    start_int, end_int = end_int, start_int
                for i in range(start_int, end_int + 1):
                    ips.append(str(ipaddress.ip_address(i)))
            else:
                try:
                    ip = ipaddress.ip_address(part)
                    ips.append(str(ip))
                except ValueError:
                    if not is_valid_domain(part):
                        logger.warning(f"Invalid target format (not IP or domain): {part}")
                        continue
                    resolved_ip = socket.gethostbyname(part)
                    ips.append(resolved_ip)
                    logger.info(f"Resolved {part} -> {resolved_ip}")
        except Exception as e:
            logger.error(f"Error parsing target '{part}': {e}")

    unique = sorted(set(ips), key=lambda ip: int(ipaddress.ip_address(ip)))
    return unique


def parse_ports(port_string: str) -> List[int]:
    if port_string.lower() == 'all':
        return list(range(1, 65536))
    elif port_string.lower() == 'top100':
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 1433, 1521, 2049, 2375, 2376,
            3128, 3268, 3269, 3333, 4243, 4343, 4443, 5000, 5001, 5432, 5555,
            5632, 5800, 5801, 5984, 5985, 5986, 6379, 7001, 7002, 8000, 8001,
            8008, 8009, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
            8090, 8181, 8444, 8445, 8446, 8447, 8880, 8888, 9000, 9001, 9043,
            9060, 9080, 9090, 9091, 9100, 9200, 9300, 9418, 9999, 10000, 10001,
            11211, 27017, 27018, 27019, 50000, 50030, 50070, 50075, 50090,
        ]
    elif port_string.lower() == 'top1000':
        return list(range(1, 1001))

    ports: List[int] = []
    parts = [p.strip() for p in port_string.split(',') if p.strip()]

    for part in parts:
        try:
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        except ValueError:
            logger.warning(f"Invalid port format: '{part}'")

    valid = sorted(set(p for p in ports if 1 <= p <= 65535))
    return valid


def resolve_domain(domain: str) -> Optional[str]:
    try:
        if not is_valid_domain(domain):
            return None
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def extract_domains(targets: List[str]) -> List[str]:
    domains = []
    for t in targets:
        if is_valid_domain(t) and not is_valid_ip(t):
            domains.append(t)
    return domains


def parse_hosts_and_ports(
    target_string: str,
    port_string: str = 'top100'
) -> Tuple[List[str], List[str], List[int]]:
    hosts = parse_targets(target_string)
    domains = [t for t in target_string.split(',') if is_valid_domain(t.strip())]
    domains = [d.strip() for d in domains]
    ports = parse_ports(port_string)
    return hosts, domains, ports