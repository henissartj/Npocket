import asyncio
import platform
from utils.logger import logger
from utils.config import config

async def async_ping_host(ip, semaphore):
    """
    Ping a single host asynchronously using the system's ping command.
    """
    async with semaphore:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_ms = str(int(config.timeout * 1000))
        
        try:
            # We use asyncio subprocess to avoid blocking the event loop
            process = await asyncio.create_subprocess_exec(
                'ping', param, '1', '-w', timeout_ms, ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            # Wait for the process to finish with a slightly higher timeout
            await asyncio.wait_for(process.communicate(), timeout=config.timeout + 1.0)
            
            is_up = (process.returncode == 0)
            if config.verbose and is_up:
                logger.debug(f"Host {ip} is up")
                
            return ip, is_up
            
        except asyncio.TimeoutError:
            if process.returncode is None:
                try:
                    process.kill()
                except Exception:
                    pass
            return ip, False
        except Exception as e:
            if config.verbose:
                logger.debug(f"Error pinging {ip}: {e}")
            return ip, False

async def discover_hosts_async(ips, progress_callback=None):
    """
    Discover active hosts in a list of IPs asynchronously.
    """
    active_hosts = []
    logger.info(f"Starting host discovery on {len(ips)} IPs...")
    
    semaphore = asyncio.Semaphore(config.concurrency)
    tasks = [asyncio.create_task(async_ping_host(ip, semaphore)) for ip in ips]
    
    completed = 0
    total = len(tasks)
    
    for coro in asyncio.as_completed(tasks):
        ip, is_up = await coro
        completed += 1
        
        if progress_callback:
            progress_callback(completed, total)
            
        if is_up:
            active_hosts.append(ip)
            
    logger.info(f"Host discovery completed. {len(active_hosts)} host(s) up.")
    return active_hosts
