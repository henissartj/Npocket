import asyncio
import re
from typing import Optional

from utils.logger import logger
from utils.config import config


HTTP_GET_PROBE = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Npocket/2.0\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: close\r\n\r\n"
HTTP_OPTIONS_PROBE = b"OPTIONS / HTTP/1.0\r\nHost: localhost\r\n\r\n"
HTTP_HEAD_PROBE = b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"


def parse_http_response(data: str) -> str:
    try:
        title_match = re.search(r'<title>(.*?)</title>', data, re.IGNORECASE | re.DOTALL)
        server_match = re.search(r'Server:\s*(.*?)\r\n', data, re.IGNORECASE)
        powered_by = re.search(r'X-Powered-By:\s*(.*?)\r\n', data, re.IGNORECASE)
        location = re.search(r'Location:\s*(.*?)\r\n', data, re.IGNORECASE)
        www_auth = re.search(r'WWW-Authenticate:\s*(.*?)\r\n', data, re.IGNORECASE)
        content_type = re.search(r'Content-Type:\s*(.*?)\r\n', data, re.IGNORECASE)
        cookies = re.search(r'Set-Cookie:\s*(.*?);', data, re.IGNORECASE)

        title = re.sub(r'\s+', ' ', title_match.group(1).strip()) if title_match else ""
        server = server_match.group(1).strip() if server_match else ""
        extra = []

        if server:
            extra.append(f"Srv:{server}")
        if powered_by:
            extra.append(f"X-Powered-By:{powered_by.group(1).strip()}")
        if title:
            extra.append(f"Title:{title[:50]}")
        if www_auth:
            extra.append(f"Auth:{www_auth.group(1).strip()}")
        if location:
            extra.append(f"->{location.group(1).strip()}")
        if cookies:
            extra.append(f"Cookie:{cookies.group(1).strip()}")

        if extra:
            first_line = data.strip().split('\r\n')[0]
            return f"{first_line[:60]} [{' | '.join(extra[:4])}]"
        return data.strip().split('\r\n')[0][:80]
    except Exception:
        return data.strip().split('\r\n')[0][:80]


def detect_protocol(port: int, banner: Optional[str]) -> str:
    if banner:
        bl = banner.lower()
        if 'ssh' in bl or 'openssh' in bl:
            return 'SSH'
        if 'ftp' in bl:
            return 'FTP'
        if 'smtp' in bl or 'esmtp' in bl:
            return 'SMTP'
        if 'pop3' in bl or bl.startswith('+ok'):
            return 'POP3'
        if 'imap' in bl or bl.startswith('* ok'):
            return 'IMAP'
        if 'mysql' in bl:
            return 'MySQL'
        if 'postgresql' in bl or 'postgres' in bl:
            return 'PostgreSQL'
        if 'redis' in bl:
            return 'Redis'
        if 'mongodb' in bl:
            return 'MongoDB'
        if 'http' in bl:
            return 'HTTP'

    port_map = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 137: 'NetBIOS-NS',
        139: 'NetBIOS-SSN', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS',
        445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP',
        636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
        1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS',
        2375: 'Docker', 2376: 'Docker-TLS', 3128: 'Squid', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB',
        6379: 'Redis', 6443: 'HTTPS-Alt', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        9090: 'HTTP-Alt', 9200: 'Elasticsearch', 9300: 'ES-Cluster',
        11211: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB-Alt',
        50000: 'DB2', 50070: 'HDFS',
    }
    return port_map.get(port, 'unknown')


async def async_grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int
) -> Optional[str]:
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=config.timeout / 2)
        if data:
            decoded = data.decode('utf-8', errors='ignore').strip()
            protocol = detect_protocol(port, decoded)
            if 'HTTP/' in decoded:
                return f"{protocol}: {parse_http_response(decoded)}"
            first_line = decoded.split('\r\n')[0][:100]
            return f"{protocol}: {first_line}"
    except asyncio.TimeoutError:
        pass

    if port in [80, 443, 8080, 8443, 8000, 8888, 9090]:
        probes = [HTTP_GET_PROBE, HTTP_HEAD_PROBE, HTTP_OPTIONS_PROBE]
    elif port in [21, 110, 143, 993, 995]:
        return None
    elif port in [22, 23]:
        return None
    elif port in [25, 465, 587]:
        probes = [b"EHLO npocket\r\n", b"HELO npocket\r\n"]
    elif port in [3306]:
        return None
    elif port in [5432]:
        return None
    elif port in [6379]:
        probes = [b"PING\r\n", b"INFO\r\n"]
    elif port in [27017]:
        return None
    else:
        probes = [HTTP_GET_PROBE]

    for probe in probes:
        try:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=config.timeout / 2)
            data = await asyncio.wait_for(reader.read(2048), timeout=config.timeout / 2)
            if data:
                decoded = data.decode('utf-8', errors='ignore')
                protocol = detect_protocol(port, decoded)
                if 'HTTP/' in decoded:
                    return f"{protocol}: {parse_http_response(decoded)}"
                first_line = decoded.strip().split('\r\n')[0][:100]
                return f"{protocol}: {first_line}"
        except Exception:
            continue

    return None