import asyncio
import re
from utils.logger import logger
from utils.config import config

def parse_http_response(data: str) -> str:
    """Extracts useful info like Server and Title from HTTP responses."""
    try:
        title_match = re.search(r'<title>(.*?)</title>', data, re.IGNORECASE | re.DOTALL)
        server_match = re.search(r'Server:\s*(.*?)\r\n', data, re.IGNORECASE)
        
        title = title_match.group(1).strip() if title_match else ""
        server = server_match.group(1).strip() if server_match else ""
        
        # Clean up title (remove newlines)
        title = re.sub(r'\s+', ' ', title)
        
        banner = data.strip().split('\r\n')[0][:50]
        
        extras = []
        if server:
            extras.append(f"Server: {server}")
        if title:
            extras.append(f"Title: {title[:40]}")
            
        if extras:
            return f"{banner} [{', '.join(extras)}]"
        return banner
    except Exception:
        return data.strip().split('\r\n')[0][:50]

async def async_grab_banner(reader, writer, port):
    """
    Attempt to grab a banner from an established async connection.
    Sends protocol-specific probes based on the port or falls back to generic HTTP.
    """
    try:
        # First, let's just listen for a bit. Some services (SSH, FTP, SMTP) 
        # send a banner immediately upon connection.
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=config.timeout / 2)
            if data:
                return data.decode('utf-8', errors='ignore').strip().split('\r\n')[0]
        except asyncio.TimeoutError:
            pass

        # If no immediate banner, send a probe based on the port
        probes = []
        if port in [80, 443, 8080, 8443]:
            probes.append(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        else:
            # Generic probe that often triggers an error message containing the server software
            probes.append(b"OPTIONS / HTTP/1.0\r\n\r\n")
            probes.append(b"\r\n\r\n")

        for probe in probes:
            try:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=config.timeout / 2)
                data = await asyncio.wait_for(reader.read(2048), timeout=config.timeout / 2)
                if data:
                    decoded = data.decode('utf-8', errors='ignore')
                    if "HTTP/" in decoded:
                        return parse_http_response(decoded)
                    return decoded.strip().split('\r\n')[0][:50]
            except Exception:
                continue

        return None
    except Exception as e:
        if config.verbose:
            logger.debug(f"Error grabbing banner on port {port}: {e}")
        return None
