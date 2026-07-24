import asyncio
import platform
import re
from typing import Dict, Optional

from utils.logger import logger
from utils.config import config


TTL_SIGNATURES: Dict[int, str] = {
    32: 'Solaris/SunOS',
    55: 'Cisco IOS',
    60: 'AIX',
    64: 'Linux/Unix',
    65: 'Linux (custom)',
    100: 'FreeBSD',
    128: 'Windows (default)',
    129: 'Windows Server',
    192: 'Cisco (some)',
    200: 'BSD/OS',
    240: 'VMS/OpenVMS',
    254: 'Solaris/AIX/Cisco',
    255: 'Network device',
}

WINDOW_SIGNATURES: Dict[int, str] = {
    65535: 'Linux',
    8192: 'Windows',
    16384: 'Windows',
    5840: 'Cisco',
    5720: 'Cisco',
    24240: 'Solaris',
    10752: 'FreeBSD',
    33304: 'macOS',
    65529: 'macOS',
}


def get_os_from_ttl(ttl: int) -> str:
    if ttl <= 1:
        return 'Unknown/Network'
    for threshold, name in sorted(TTL_SIGNATURES.items()):
        if ttl <= threshold:
            return name
    return 'Unknown/Embedded'


async def async_fingerprint_os(ip: str) -> str:
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
            match = re.search(r'TTL=(\d+)', output, re.IGNORECASE)
            if match:
                ttl = int(match.group(1))
                os_guess = get_os_from_ttl(ttl)
                if config.verbose:
                    logger.debug(f"OS fingerprint {ip}: TTL={ttl} -> {os_guess}")
                return os_guess
            else:
                return 'Unknown (no TTL)'
        return 'Unknown (host down)'
    except asyncio.TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except Exception:
                pass
        return 'Unknown (timeout)'
    except Exception as e:
        logger.error(f"Error fingerprinting OS for {ip}: {e}")
        return 'Unknown'