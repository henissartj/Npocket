import asyncio
import socket
from utils.logger import logger
from utils.config import config
from scan.service import async_grab_banner

async def scan_tcp_port_async(ip, port, semaphore):
    """
    Perform a TCP connect scan on a single port asynchronously.
    Also dynamically adjusts timeout if smart timing is enabled.
    """
    async with semaphore:
        start_time = asyncio.get_event_loop().time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=config.timeout
            )
            
            # Smart Adaptive Timing Logic
            if getattr(config, 'adaptive_timing', False):
                elapsed = asyncio.get_event_loop().time() - start_time
                # Decrease timeout if connection was very fast
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
                
            return port, 'tcp', 'open', service_banner
            
        except asyncio.TimeoutError:
            if getattr(config, 'adaptive_timing', False):
                config.timeout_strikes = getattr(config, 'timeout_strikes', 0) + 1
                if config.timeout_strikes > 5:
                    config.timeout = min(5.0, config.timeout * 1.1)
                    config.timeout_strikes = 0
            return port, 'tcp', 'filtered', None
        except Exception:
            # Usually ConnectionRefusedError
            return port, 'tcp', 'closed', None

class UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_con_lost):
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        pass

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)

async def scan_udp_port_async(ip, port, semaphore):
    """
    Perform a basic UDP scan.
    """
    async with semaphore:
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
            
            # Send an empty UDP packet
            transport.sendto(b'')
            
            # Wait for a brief period to see if ICMP Port Unreachable comes back
            # or if we get a response. In Python without raw sockets, UDP is tricky.
            # A timeout generally means open|filtered.
            try:
                await asyncio.wait_for(on_con_lost, timeout=config.timeout)
                return port, 'udp', 'closed', None
            except asyncio.TimeoutError:
                return port, 'udp', 'open|filtered', None
            finally:
                transport.close()
                
        except Exception:
            return port, 'udp', 'closed', None

async def scan_ports_async(ip, ports, scan_type='tcp', progress_callback=None):
    """
    Scan a list of ports on a specific IP using Asyncio.
    """
    open_ports = []
    semaphore = asyncio.Semaphore(config.concurrency)
    tasks = []
    
    for port in ports:
        if scan_type == 'tcp':
            tasks.append(asyncio.create_task(scan_tcp_port_async(ip, port, semaphore)))
        elif scan_type == 'udp':
            tasks.append(asyncio.create_task(scan_udp_port_async(ip, port, semaphore)))

    completed = 0
    total = len(tasks)
    
    # Process as they complete
    for coro in asyncio.as_completed(tasks):
        port, protocol, state, banner = await coro
        completed += 1
        
        if progress_callback:
            progress_callback(completed, total)
            
        if 'open' in state:
            open_ports.append({
                'port': port,
                'protocol': protocol,
                'state': state,
                'service': banner
            })
            
    return open_ports
