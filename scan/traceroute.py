import asyncio
import platform
import re
from typing import List, Optional, Tuple

from utils.logger import logger
from utils.config import config


async def trace_host(target: str, max_hops: int = 30) -> List[Tuple[int, str, float]]:
    hops: List[Tuple[int, str, float]] = []
    system = platform.system().lower()

    if system == 'windows':
        param_n = '-h'
    else:
        param_n = '-m'

    timeout_ms = str(int(config.timeout * 1000))

    try:
        process = await asyncio.create_subprocess_exec(
            'tracert' if system == 'windows' else 'traceroute',
            param_n, str(max_hops),
            '-w', timeout_ms, target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )

        stdout, _ = await asyncio.wait_for(
            process.communicate(),
            timeout=config.timeout * max_hops + 10
        )

        output = stdout.decode('utf-8', errors='ignore')
        hop_pattern = re.compile(r'\s*(\d+)\s+\*?\s*(?:(\d+\.\d+\.\d+\.\d+|<unknown>|<1 ms|[<\d]+\s*ms))\s*(?:(\d+\.\d+\.\d+\.\d+))?', re.I)

        if system == 'windows':
            for line in output.split('\n'):
                match = re.match(r'\s*(\d+)\s+<?(\d+)\s*ms\s+<?(\d+)\s*ms\s+<?(\d+)\s*ms\s+(\S+)', line)
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(5)
                    if hop_ip != '*':
                        hops.append((hop_num, hop_ip, 0.0))
        else:
            for line in output.split('\n'):
                parts = line.strip().split()
                if parts and parts[0].isdigit():
                    hop_num = int(parts[0])
                    for part in parts[1:]:
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', part):
                            hops.append((hop_num, part, 0.0))
                            break

    except FileNotFoundError:
        logger.warning("traceroute/tracert not available on this system")
    except asyncio.TimeoutError:
        logger.warning("Traceroute timed out")
    except Exception as e:
        logger.error(f"Traceroute error for {target}: {e}")

    return hops


async def run_traceroute(target: str) -> List[Tuple[int, str, float]]:
    logger.info(f"Tracing route to {target}...")
    hops = await trace_host(target)
    if hops:
        logger.info(f"Traceroute complete: {len(hops)} hop(s)")
        for hop_num, hop_ip, rtt in hops:
            logger.info(f"  {hop_num}. {hop_ip}")
    else:
        logger.warning("No traceroute results")
    return hops