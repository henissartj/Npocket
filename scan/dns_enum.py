import asyncio
import socket
import struct
from typing import Dict, List, Optional, Tuple

from utils.logger import logger
from utils.config import config


DNS_HEADER = struct.Struct('!HHHHHH')

QTYPES: Dict[str, int] = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'SRV': 33, 'CAA': 257,
}

QCLASS_IN = 1


def build_dns_query(domain: str, qtype: int) -> bytes:
    tid = 0x0001
    flags = 0x0100
    qdcount = 1
    header = DNS_HEADER.pack(tid, flags, qdcount, 0, 0, 0)

    labels = domain.split('.')
    question = b''
    for label in labels:
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'
    question += struct.pack('!HH', qtype, QCLASS_IN)

    return header + question


def parse_dns_response(data: bytes) -> List[str]:
    results: List[str] = []

    try:
        header = DNS_HEADER.unpack(data[:12])
        tid, flags, qdcount, ancount, nscount, arcount = header
        rcode = flags & 0x000F

        if rcode != 0:
            return []

        offset = 12
        for _ in range(qdcount):
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 5

        for _ in range(ancount):
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1

            rtype, rclass, ttl, rdlength = struct.unpack_from('!HHIH', data, offset)
            offset += 10

            if rtype == 1:
                ip = socket.inet_ntoa(data[offset:offset + 4])
                results.append(ip)
                offset += rdlength
            elif rtype == 28:
                ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                results.append(ip)
                offset += rdlength
            elif rtype in (2, 5):
                name = _parse_name(data, offset)
                results.append(name)
                offset += rdlength
            elif rtype == 15:
                pref, = struct.unpack_from('!H', data, offset)
                name = _parse_name(data, offset + 2)
                results.append(f"{name} (priority {pref})")
                offset += rdlength
            elif rtype == 16:
                txt_len = data[offset]
                txt = data[offset + 1:offset + 1 + txt_len].decode(errors='ignore')
                results.append(txt)
                offset += rdlength
            elif rtype == 6:
                mname = _parse_name(data, offset)
                offset += _name_len(data, offset)
                rname = _parse_name(data, offset)
                offset += _name_len(data, offset)
                serial, refresh, retry, expire, minimum = struct.unpack_from('!IIIII', data, offset)
                results.append(f"MNAME={mname} RNAME={rname} Serial={serial}")
                offset += rdlength - (_name_len(data, offset - _name_len(data, offset - _name_len(data, offset))) + _name_len(data, offset))
            else:
                offset += rdlength
    except Exception as e:
        if config.verbose:
            logger.debug(f"DNS parse error: {e}")

    return results


def _parse_name(data: bytes, offset: int) -> str:
    labels: List[str] = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = struct.unpack_from('!H', data, offset)[0] & 0x3FFF
            labels.append(_parse_name(data, ptr))
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode(errors='ignore'))
        offset += length
    return '.'.join(labels)


def _name_len(data: bytes, offset: int) -> int:
    start = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            offset += 2
            break
        offset += 1 + length
    return offset - start


async def query_dns_record(
    domain: str,
    qtype: str = 'A',
    server: str = '8.8.8.8'
) -> List[str]:
    qtype_code = QTYPES.get(qtype, 1)
    query = build_dns_query(domain, qtype_code)

    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()

    transport: Optional[asyncio.DatagramTransport] = None
    results: List[str] = []

    class DNSProtocol(asyncio.DatagramProtocol):
        def connection_made(self, tr):
            nonlocal transport
            transport = tr
            tr.sendto(query, (server, 53))

        def datagram_received(self, data, addr):
            nonlocal results
            results = parse_dns_response(data)
            if not on_con_lost.done():
                on_con_lost.set_result(True)

        def error_received(self, exc):
            if not on_con_lost.done():
                on_con_lost.set_result(True)

        def connection_lost(self, exc):
            if not on_con_lost.done():
                on_con_lost.set_result(True)

    try:
        transport, _ = await loop.create_datagram_endpoint(
            DNSProtocol,
            family=socket.AF_INET
        )
        await asyncio.wait_for(on_con_lost, timeout=config.timeout)
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        if config.verbose:
            logger.debug(f"DNS query error for {domain} {qtype}: {e}")
    finally:
        if transport:
            transport.close()

    return results


async def enumerate_dns(domain: str) -> Dict[str, List[str]]:
    logger.info(f"Enumerating DNS records for {domain}...")
    results: Dict[str, List[str]] = {}

    dns_server = config.dns_server or '8.8.8.8'

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for rtype in record_types:
        try:
            records = await query_dns_record(domain, rtype, dns_server)
            if records:
                results[rtype] = records
                for rec in records:
                    logger.info(f"  {rtype}: {rec}")
        except Exception as e:
            if config.verbose:
                logger.debug(f"DNS {rtype} query failed for {domain}: {e}")

    logger.info(f"DNS enumeration complete for {domain}: {sum(len(v) for v in results.values())} records found")
    return results