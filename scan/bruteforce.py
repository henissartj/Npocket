import asyncio
import base64
from typing import Dict, List, Optional, Tuple

from utils.logger import logger
from utils.config import config


FTP_CREDENTIALS: List[Tuple[str, str]] = [
    ("anonymous", "anonymous"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "12345"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("ftp", "ftp"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", "admin123"),
    ("test", "test"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("cisco", "cisco"),
    ("support", "support"),
]

SSH_CREDENTIALS: List[Tuple[str, str]] = [
    ("root", "root"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "12345"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("admin", "admin123"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("vagrant", "vagrant"),
    ("centos", "centos"),
]

HTTP_AUTH_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "admin"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    ("guest", "guest"),
    ("", "admin"),
    ("", "password"),
]


async def bruteforce_ftp(ip: str, port: int, creds: List[Tuple[str, str]]) -> Optional[str]:
    for user, pwd in creds:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=config.timeout
            )
            await asyncio.wait_for(reader.read(1024), timeout=config.timeout)

            writer.write(f"USER {user}\r\n".encode())
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=config.timeout)

            writer.write(f"PASS {pwd}\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=config.timeout)

            writer.close()
            await writer.wait_closed()

            resp_str = resp.decode(errors='ignore')
            if "230" in resp_str or "Login successful" in resp_str:
                return f"SUCCESS ({user}:{pwd})"
        except Exception:
            pass
    return None


async def bruteforce_ssh(ip: str, port: int, creds: List[Tuple[str, str]]) -> Optional[str]:
    for user, pwd in creds:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=config.timeout
            )
            await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
            writer.write(f"{user}\n".encode())
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
            writer.write(f"{pwd}\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=config.timeout)

            writer.close()
            await writer.wait_closed()

            resp_str = resp.decode(errors='ignore')
            if "success" in resp_str.lower() or "welcome" in resp_str.lower() or "$" in resp_str or "#" in resp_str:
                return f"SUCCESS ({user}:{pwd})"
        except Exception:
            pass
    return None


async def bruteforce_http_auth(ip: str, port: int, creds: List[Tuple[str, str]]) -> Optional[str]:
    for user, pwd in creds:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=config.timeout
            )
            auth_str = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"Authorization: Basic {auth_str}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            writer.write(request)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(2048), timeout=config.timeout)

            writer.close()
            await writer.wait_closed()

            resp_str = resp.decode(errors='ignore')
            if "HTTP/1.1 200 OK" in resp_str or "HTTP/1.0 200 OK" in resp_str:
                return f"SUCCESS ({user}:{pwd})"
            if "HTTP/1.1 401" not in resp_str and "HTTP/1.0 401" not in resp_str:
                if "HTTP/1.1 403" not in resp_str and "HTTP/1.0 403" not in resp_str:
                    pass
        except Exception:
            pass
    return None


def load_wordlist(path: str) -> List[Tuple[str, str]]:
    creds: List[Tuple[str, str]] = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    user, pwd = line.split(':', 1)
                    creds.append((user.strip(), pwd.strip()))
                elif line:
                    creds.append((line, line))
        logger.info(f"Loaded {len(creds)} credentials from {path}")
    except Exception as e:
        logger.error(f"Error loading wordlist {path}: {e}")
    return creds


async def run_bruteforce(results: Dict) -> None:
    logger.info("Starting intellignt bruteforce on discovered services...")

    creds = list(FTP_CREDENTIALS)
    ssh_creds = list(SSH_CREDENTIALS)
    http_creds = list(HTTP_AUTH_CREDENTIALS)

    if config.bruteforce_wordlist:
        extra = load_wordlist(config.bruteforce_wordlist)
        if extra:
            creds = extra + creds
            ssh_creds = extra + ssh_creds
            http_creds = extra + http_creds

    for ip, data in results.items():
        for port_info in data.get('ports', []):
            if port_info['state'] != 'open':
                continue
            port = port_info['port']
            service_info = str(port_info.get('service', '')).lower()

            if port == 21 or "ftp" in service_info:
                logger.info(f"Bruteforcing FTP {ip}:{port}...")
                res = await bruteforce_ftp(ip, port, creds)
                if res:
                    port_info['bruteforce'] = f"FTP {res}"
                    logger.info(f"[!] FTP vulnerable: {ip}:{port} -> {res}")

            if port == 22 or "ssh" in service_info:
                logger.info(f"Bruteforcing SSH {ip}:{port}...")
                res = await bruteforce_ssh(ip, port, ssh_creds)
                if res:
                    port_info['bruteforce'] = f"SSH {res}"
                    logger.info(f"[!] SSH vulnerable: {ip}:{port} -> {res}")

            if port in [80, 443, 8080, 8443] and ("http" in service_info or not service_info):
                logger.info(f"Bruteforcing HTTP Auth {ip}:{port}...")
                res = await bruteforce_http_auth(ip, port, http_creds)
                if res:
                    port_info['bruteforce'] = f"HTTP Auth {res}"
                    logger.info(f"[!] HTTP Auth vulnerable: {ip}:{port} -> {res}")