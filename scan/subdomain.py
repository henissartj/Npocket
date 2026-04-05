import asyncio
import socket
from utils.logger import logger
from utils.config import config
from utils.ui import print_progress_bar

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", 
    "webdisk", "server", "cpanel", "whm", "autodiscover", "autoconfig", 
    "m", "imap", "test", "ns2", "blog", "dev", "api", "admin", "vpn", 
    "cloud", "firewall", "staging", "secure", "gw", "portal", "shop"
]

async def resolve_subdomain(subdomain, domain, sem):
    target = f"{subdomain}.{domain}"
    loop = asyncio.get_event_loop()
    try:
        async with sem:
            # gethostbyname is blocking, run in executor
            result = await loop.run_in_executor(None, socket.gethostbyname, target)
            return target, result
    except Exception:
        return None, None

async def enumerate_subdomains(domain):
    logger.info(f"Starting subdomain enumeration for {domain}...")
    sem = asyncio.Semaphore(config.concurrency)
    tasks = []
    
    for sub in COMMON_SUBDOMAINS:
        tasks.append(resolve_subdomain(sub, domain, sem))
        
    discovered = []
    completed = 0
    total = len(tasks)
    
    for coro in asyncio.as_completed(tasks):
        target, ip = await coro
        completed += 1
        if config.show_progress:
            print_progress_bar(completed, total, prefix='Subdomain Enum:', suffix='Complete', length=30)
        if target and ip:
            discovered.append((target, ip))
            
    print() # Newline after progress bar
    
    for target, ip in discovered:
        logger.info(f"[+] Discovered subdomain: {target} ({ip})")
        
    return discovered
