import asyncio
import platform
import re
from utils.logger import logger
from utils.config import config

def get_os_from_ttl(ttl):
    """
    Guess the OS family based on the initial TTL value.
    Common default TTLs:
    - Linux/Unix: 64 (or slightly less due to hops)
    - Windows: 128 (or slightly less)
    - Solaris/AIX/Cisco: 254 (or slightly less)
    """
    if ttl <= 64:
        return 'Linux/Unix'
    elif ttl <= 128:
        return 'Windows'
    else:
        return 'Unknown/Solaris/Router'

async def async_fingerprint_os(ip):
    """
    Perform a simple OS fingerprinting asynchronously by sending a ping and analyzing the TTL.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_ms = str(int(config.timeout * 1000))
    
    try:
        process = await asyncio.create_subprocess_exec(
            'ping', param, '1', '-w', timeout_ms, ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=config.timeout + 1.0)
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            # Look for TTL in the output
            match = re.search(r'TTL=(\d+)', output, re.IGNORECASE)
            if match:
                ttl = int(match.group(1))
                os_guess = get_os_from_ttl(ttl)
                if config.verbose:
                    logger.debug(f"OS Fingerprinting for {ip}: TTL={ttl} -> {os_guess}")
                return os_guess
            else:
                logger.debug(f"TTL not found in ping response for {ip}")
                return 'Unknown'
        else:
            return 'Unknown'
            
    except asyncio.TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except Exception:
                pass
        return 'Unknown'
    except Exception as e:
        logger.error(f"Error fingerprinting OS for {ip}: {e}")
        return 'Unknown'
