import asyncio
from utils.logger import logger
from utils.config import config

CREDENTIALS = [
    ("anonymous", "anonymous"),
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
    ("admin", "12345")
]

async def bruteforce_ftp(ip, port):
    """
    Attempt basic intelligent FTP login bruteforce.
    """
    for user, pwd in CREDENTIALS:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=config.timeout)
            
            # Read welcome banner
            await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
            
            # Send USER
            writer.write(f"USER {user}\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
            
            # Send PASS
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
    return "Failed"

async def run_bruteforce(results):
    """
    Iterate over results and run intelligent bruteforce on discovered vulnerable services.
    """
    logger.info("Starting Basic Intelligent Bruteforce on discovered services...")
    for ip, data in results.items():
        for port_info in data.get('ports', []):
            if port_info['state'] == 'open':
                port = port_info['port']
                service_info = str(port_info.get('service', '')).lower()
                
                # Check if it's FTP
                if port == 21 or "ftp" in service_info:
                    logger.info(f"Attempting FTP bruteforce on {ip}:{port}...")
                    res = await bruteforce_ftp(ip, port)
                    port_info['bruteforce'] = res
                    if "SUCCESS" in res:
                        logger.info(f"[!] Vulnerable to FTP Bruteforce: {ip}:{port} -> {res}")
