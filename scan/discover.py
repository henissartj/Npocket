import asyncio
import platform
from typing import Callable, List, Optional

from utils.logger import logger
from utils.config import config


async def async_ping_host(ip: str, semaphore: asyncio.Semaphore) -> tuple:
    async with semaphore:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_ms = str(int(config.timeout * 1000))

        try:
            process = await asyncio.create_subprocess_exec(
                'ping', param, '1', '-w', timeout_ms, ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(process.communicate(), timeout=config.timeout + 1.0)
            is_up = (process.returncode == 0)
            if config.verbose and is_up:
                logger.debug(f"Host {ip} is up (ping)")
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


async def async_tcp_ping_host(ip: str, semaphore: asyncio.Semaphore, port: int = 80) -> tuple:
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=config.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if config.verbose:
                logger.debug(f"Host {ip} is up (TCP ping port {port})")
            return ip, True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return ip, False
        except Exception as e:
            if config.verbose:
                logger.debug(f"Error TCP-pinging {ip}:{port}: {e}")
            return ip, False


async def discover_hosts_async(
    ips: List[str],
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> List[str]:
    active_hosts: List[str] = []
    logger.info(f"Starting host discovery on {len(ips)} IP(s)...")

    semaphore = asyncio.Semaphore(min(config.concurrency, 200))
    use_tcp_ping = config.tcp_ping or platform.system().lower() != 'windows'

    if use_tcp_ping:
        ping_port = config.tcp_ping_port
        logger.debug(f"Using TCP ping on port {ping_port} (faster, no admin needed)")
        tasks = [asyncio.create_task(async_tcp_ping_host(ip, semaphore, ping_port)) for ip in ips]
    else:
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

    logger.info(f"Discovery: {len(active_hosts)}/{len(ips)} host(s) are up.")
    return active_hosts