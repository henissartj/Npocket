import asyncio
import time
from typing import Callable, Dict, List, Optional

from utils.logger import logger
from utils.config import config
from scan.service import async_grab_banner


async def scan_tcp_port_async(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    rate_limiter: Optional['RateLimiter'] = None
) -> Dict:
    async with semaphore:
        if rate_limiter:
            await rate_limiter.wait()

        start_time = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=config.timeout
            )

            if getattr(config, 'adaptive_timing', False):
                elapsed = time.monotonic() - start_time
                config.timeout = max(0.5, (config.timeout * 0.9) + (elapsed * 0.1))
                config.timeout_strikes = max(0, getattr(config, 'timeout_strikes', 0) - 1)

            if config.verbose:
                logger.debug(f"Port {port}/tcp is open on {ip}")

            service_banner = None
            if config.service_detection:
                service_banner = await async_grab_banner(reader, writer, port)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            result = {
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': service_banner
            }
            if config.adaptive_timing:
                result['latency'] = round((time.monotonic() - start_time) * 1000, 1)
            return result

        except asyncio.TimeoutError:
            if getattr(config, 'adaptive_timing', False):
                config.timeout_strikes = getattr(config, 'timeout_strikes', 0) + 1
                if config.timeout_strikes > 5:
                    config.timeout = min(5.0, config.timeout * 1.1)
                    config.timeout_strikes = 0
            return {'port': port, 'protocol': 'tcp', 'state': 'filtered', 'service': None}
        except Exception:
            return {'port': port, 'protocol': 'tcp', 'state': 'closed', 'service': None}


class UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_con_lost: asyncio.Future) -> None:
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        pass

    def error_received(self, exc: Exception) -> None:
        pass

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)


async def scan_udp_port_async(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    rate_limiter: Optional['RateLimiter'] = None
) -> Dict:
    async with semaphore:
        if rate_limiter:
            await rate_limiter.wait()

        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        try:
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    lambda: UdpProtocol(on_con_lost),
                    remote_addr=(ip, port)
                ),
                timeout=config.timeout
            )
            transport.sendto(b'')

            try:
                await asyncio.wait_for(on_con_lost, timeout=config.timeout)
                return {'port': port, 'protocol': 'udp', 'state': 'closed', 'service': None}
            except asyncio.TimeoutError:
                return {'port': port, 'protocol': 'udp', 'state': 'open|filtered', 'service': None}
            finally:
                transport.close()
        except Exception:
            return {'port': port, 'protocol': 'udp', 'state': 'closed', 'service': None}


class RateLimiter:
    def __init__(self, max_per_second: float = 0) -> None:
        self._max = max_per_second
        self._tokens = 0.0
        self._last = time.monotonic()

    async def wait(self) -> None:
        if self._max <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self._max, self._tokens + elapsed * self._max)
        self._last = now
        if self._tokens < 1:
            wait_time = (1 - self._tokens) / self._max
            await asyncio.sleep(wait_time)
            self._tokens = 0.0
        else:
            self._tokens -= 1.0


async def scan_ports_async(
    ip: str,
    ports: List[int],
    scan_type: str = 'tcp',
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> List[Dict]:
    open_ports: List[Dict] = []
    semaphore = asyncio.Semaphore(config.concurrency)
    rate_limiter = RateLimiter(config.rate_limit) if config.rate_limit > 0 else None

    tasks = []
    for port in ports:
        if scan_type == 'tcp':
            tasks.append(asyncio.create_task(scan_tcp_port_async(ip, port, semaphore, rate_limiter)))
        elif scan_type == 'udp':
            tasks.append(asyncio.create_task(scan_udp_port_async(ip, port, semaphore, rate_limiter)))

    completed = 0
    total = len(tasks)

    for coro in asyncio.as_completed(tasks):
        result = await coro
        completed += 1
        if progress_callback:
            progress_callback(completed, total)
        if 'open' in result['state']:
            open_ports.append(result)

    return open_ports