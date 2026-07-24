import argparse
import asyncio
import logging
import os
import platform
import socket
import sys
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logger import setup_logger, logger
from utils.config import config
from utils.ui import print_progress_bar, Colors, Spinner, get_terminal_width
from parse.parser import parse_targets, parse_ports, extract_domains, is_valid_domain, is_valid_ip
from scan.discover import discover_hosts_async
from scan.port_scan import scan_ports_async
from scan.os_fingerprint import async_fingerprint_os
from report.formatter import (
    print_banner, print_results, print_scan_summary,
    print_vuln_summary, print_discovered_subdomains
)
from report.exporter import export_results, export_all_formats


def print_custom_help() -> None:
    left_col = 28
    print(f"\n{Colors.BOLD}{Colors.OKCYAN}Usage: npocket [options] <target>{Colors.ENDC}\n")

    sections = [
        ("TARGET SPECIFICATION", [
            ("target", "IP, domain, CIDR (10.0.0.0/24), or range (10.0.0.1-50)"),
            ("-sD, --subdomains", "Enumerate 150+ common subdomains"),
            ("-D, --dns-enum", "Enumerate DNS records (A, MX, NS, TXT, SOA, CNAME)"),
        ]),
        ("PORT SPECIFICATION", [
            ("-p, --ports PORTS", "Ports: 80,443, 1000-2000, all, top100 (default)"),
            ("--top1000", "Scan first 1000 ports"),
        ]),
        ("SCAN TECHNIQUES", [
            ("-sS, --tcp", "TCP Connect Scan (default)"),
            ("-sU, --udp", "UDP Scan"),
            ("-sn, --ping-scan", "Ping scan only (disable port scanning)"),
            ("-sV, --service", "Service & version detection (banner grabbing)"),
            ("-O, --os-fingerprint", "Heuristic OS fingerprinting via TTL"),
            ("-T, --traceroute", "Trace route to target"),
        ]),
        ("ENUMERATION & ATTACK", [
            ("-B, --bruteforce", "Bruteforce FTP, SSH, HTTP Auth"),
            ("-w, --wordlist FILE", "Custom credentials wordlist for bruteforce"),
            ("-V, --vuln-check", "Banner-based vulnerability detection"),
            ("-W, --tech-detect", "Web technology fingerprinting"),
        ]),
        ("PERFORMANCE & TIMING", [
            ("-T, --timeout SEC", "Connection timeout in seconds (default: 1.5)"),
            ("-c, --concurrency N", "Concurrent tasks (default: 500)"),
            ("--smart", "Adaptive timing (dynamic timeout adjustment)"),
            ("--rate-limit N", "Max packets per second (default: unlimited)"),
            ("--aggressive", "Aggressive mode (faster, less accurate)"),
            ("--skip-discovery", "Skip ping sweep, scan all targets"),
        ]),
        ("OUTPUT & DISPLAY", [
            ("-v, --verbose", "Verbose/debug output"),
            ("--no-progress", "Disable progress bar"),
            ("--log-file FILE", "Log to file"),
            ("-oJ, --output-json FILE", "Export JSON"),
            ("-oC, --output-csv FILE", "Export CSV"),
            ("-oM, --output-md FILE", "Export Markdown"),
            ("-oH, --output-html FILE", "Export HTML dashboard"),
            ("-oA, --output-all FILE", "Export all formats (JSON+CSV+MD+HTML)"),
        ]),
        ("INTERACTIVE", [
            ("-i, --interactive", "Interactive guided scan mode"),
        ]),
        ("GENERAL", [
            ("-h, --help", "Show this help message"),
            ("--version", "Show version"),
        ]),
    ]

    for header, commands in sections:
        print(f"{Colors.OKBLUE}[+] {Colors.BOLD}{Colors.HEADER}{header}{Colors.ENDC}")
        for cmd, desc in commands:
            print(f"    {Colors.OKGREEN}{cmd.ljust(left_col)}{Colors.ENDC} {desc}")
        print()


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('targets', nargs='?', default=None)

    parser.add_argument('-sD', '--subdomains', action='store_true')
    parser.add_argument('-D', '--dns-enum', action='store_true')

    parser.add_argument('-p', '--ports', default='top100')
    parser.add_argument('--top1000', action='store_true')

    parser.add_argument('-sS', '--tcp', action='store_true')
    parser.add_argument('-sU', '--udp', action='store_true')
    parser.add_argument('-sn', '--ping-scan', action='store_true')
    parser.add_argument('-sV', '--service', action='store_true')
    parser.add_argument('-O', '--os-fingerprint', action='store_true')
    parser.add_argument('-T', '--traceroute', action='store_true')

    parser.add_argument('-B', '--bruteforce', action='store_true')
    parser.add_argument('-w', '--wordlist', type=str, default=None)
    parser.add_argument('-V', '--vuln-check', action='store_true')
    parser.add_argument('-W', '--tech-detect', action='store_true')

    parser.add_argument('--timeout', type=float, default=1.5)
    parser.add_argument('-c', '--concurrency', type=int, default=500)
    parser.add_argument('--smart', action='store_true')
    parser.add_argument('--rate-limit', type=float, default=0.0)
    parser.add_argument('--aggressive', action='store_true')
    parser.add_argument('--skip-discovery', action='store_true')

    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--no-progress', action='store_true')
    parser.add_argument('--log-file', type=str, default=None)

    parser.add_argument('-oJ', '--output-json', type=str, default=None)
    parser.add_argument('-oC', '--output-csv', type=str, default=None)
    parser.add_argument('-oM', '--output-md', type=str, default=None)
    parser.add_argument('-oH', '--output-html', type=str, default=None)
    parser.add_argument('-oA', '--output-all', type=str, default=None)

    parser.add_argument('-i', '--interactive', action='store_true')
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('--version', action='store_true')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_banner()
        print_custom_help()
        sys.exit(0)

    if '--version' in sys.argv:
        print(f"Npocket v2.0.0")
        sys.exit(0)

    return parser.parse_args()


async def interactive_mode() -> Dict:
    print_banner()
    print(f"{Colors.BOLD}{Colors.OKCYAN}Interactive Scan Mode{Colors.ENDC}\n")

    target = input(f"{Colors.OKGREEN}[?] Target (IP/domain/CIDR): {Colors.ENDC}").strip()
    if not target:
        logger.error("No target specified.")
        sys.exit(1)

    port_choice = input(f"{Colors.OKGREEN}[?] Ports [top100/top1000/all/custom]: {Colors.ENDC}").strip() or 'top100'
    if port_choice.lower() == 'custom':
        port_choice = input(f"{Colors.OKGREEN}[?] Enter ports (e.g. 80,443,1000-2000): {Colors.ENDC}").strip()

    scan_type = 'tcp'
    st = input(f"{Colors.OKGREEN}[?] Scan type [tcp/udp] (default: tcp): {Colors.ENDC}").strip().lower()
    if st == 'udp':
        scan_type = 'udp'

    features = []
    if input(f"{Colors.OKGREEN}[?] Service detection? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('service')
    if input(f"{Colors.OKGREEN}[?] OS fingerprinting? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('os')
    if input(f"{Colors.OKGREEN}[?] Subdomain enumeration? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('subdomains')
    if input(f"{Colors.OKGREEN}[?] DNS enumeration? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('dns')
    if input(f"{Colors.OKGREEN}[?] Bruteforce common creds? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('bruteforce')
    if input(f"{Colors.OKGREEN}[?] Vulnerability check? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('vuln')
    if input(f"{Colors.OKGREEN}[?] Web tech detection? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('tech')
    if input(f"{Colors.OKGREEN}[?] Traceroute? [y/N]: {Colors.ENDC}").strip().lower() == 'y':
        features.append('traceroute')

    output = input(f"{Colors.OKGREEN}[?] Output format [json/csv/md/html/all/none] (default: none): {Colors.ENDC}").strip().lower()
    output_file = None
    if output and output != 'none':
        fname = input(f"{Colors.OKGREEN}[?] Output filename: {Colors.ENDC}").strip()
        if fname:
            output_file = fname
            output_format = output
        else:
            output_file = None
    else:
        output_format = None

    concurrency_input = input(f"{Colors.OKGREEN}[?] Concurrency [default: 500]: {Colors.ENDC}").strip()
    concurrency = int(concurrency_input) if concurrency_input.isdigit() else 500

    timeout_input = input(f"{Colors.OKGREEN}[?] Timeout in seconds [default: 1.5]: {Colors.ENDC}").strip()
    timeout = float(timeout_input) if timeout_input else 1.5

    return {
        'target': target,
        'ports': port_choice,
        'scan_type': scan_type,
        'features': features,
        'output_format': output_format,
        'output_file': output_file,
        'concurrency': concurrency,
        'timeout': timeout,
    }


async def main_async() -> None:
    # Prompt for interactive mode before parsing normal args
    if '-i' in sys.argv or '--interactive' in sys.argv:
        interactive_settings = await interactive_mode()
        target_string = interactive_settings['target']
        port_string = interactive_settings['ports']
        scan_type = interactive_settings['scan_type']
        features = interactive_settings['features']
        output_format = interactive_settings['output_format']
        output_file = interactive_settings['output_file']

        config.concurrency = interactive_settings['concurrency']
        config.timeout = interactive_settings['timeout']
        config.service_detection = 'service' in features
        config.os_fingerprint = 'os' in features
        config.subdomain_enum = 'subdomains' in features
        config.dns_enum = 'dns' in features
        config.bruteforce = 'bruteforce' in features
        config.vuln_check = 'vuln' in features
        config.tech_detect = 'tech' in features
        config.traceroute = 'traceroute' in features
        config.scan_type = scan_type
        if output_format and output_file:
            config.output_format = output_format
            config.output_file = output_file
    else:
        args = parse_args()
        target_string = args.targets
        port_string = args.ports

        if args.top1000:
            port_string = 'top1000'

        config.timeout = args.timeout
        config.concurrency = args.concurrency
        config.rate_limit = args.rate_limit
        config.verbose = args.verbose
        config.service_detection = args.service
        config.os_fingerprint = args.os_fingerprint
        config.subdomain_enum = args.subdomains
        config.dns_enum = getattr(args, 'dns_enum', False)
        config.bruteforce = args.bruteforce
        config.vuln_check = getattr(args, 'vuln_check', False)
        config.tech_detect = getattr(args, 'tech_detect', False)
        config.traceroute = getattr(args, 'traceroute', False)
        config.show_progress = not args.no_progress
        config.adaptive_timing = args.smart
        config.skip_discovery = args.skip_discovery
        config.aggressive = args.aggressive
        config.log_file = args.log_file
        config.bruteforce_wordlist = args.wordlist

        scan_type = 'udp' if args.udp else 'tcp'
        config.scan_type = scan_type

        if args.output_json:
            config.output_format = 'json'
            config.output_file = args.output_json
        elif args.output_csv:
            config.output_format = 'csv'
            config.output_file = args.output_csv
        elif args.output_md:
            config.output_format = 'md'
            config.output_file = args.output_md
        elif args.output_html:
            config.output_format = 'html'
            config.output_file = args.output_html
        elif args.output_all:
            config.output_format = 'all'
            config.output_file = args.output_all

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        if args.log_file:
            setup_logger(level=logger.level, log_file=args.log_file)

    print_banner()

    if not target_string:
        logger.error("No targets specified. Use -h for help.")
        sys.exit(1)

    if config.aggressive:
        config.timeout = max(0.3, config.timeout * 0.6)
        config.concurrency = min(2000, config.concurrency * 2)

    start_time = time.monotonic()

    # Parse targets
    logger.info("Parsing targets and ports...")
    target_ips = parse_targets(target_string)
    ports_to_scan = parse_ports(port_string)
    domains = extract_domains([target_string])

    if not target_ips:
        logger.error("No valid targets found.")
        sys.exit(1)

    config.targets = target_ips
    config.ports = ports_to_scan

    logger.info(f"Targets: {len(target_ips)} IP(s), {len(ports_to_scan)} port(s) per host")

    # Subdomain enumeration
    subdomain_results = []
    if config.subdomain_enum and domains:
        from scan.subdomain import enumerate_subdomains
        for domain in domains:
            discovered = await enumerate_subdomains(domain)
            subdomain_results.extend(discovered)
            for sub, ip in discovered:
                if ip not in target_ips:
                    target_ips.append(ip)
        print_discovered_subdomains(subdomain_results)
        config.targets = target_ips

    # DNS Enumeration
    dns_results = {}
    if config.dns_enum and domains:
        from scan.dns_enum import enumerate_dns
        for domain in domains:
            dns_results[domain] = await enumerate_dns(domain)

    # Traceroute
    traceroute_results = {}
    if config.traceroute:
        from scan.traceroute import run_traceroute
        for target in target_ips[:3]:
            hops = await run_traceroute(target)
            if hops:
                traceroute_results[target] = hops

    # Host Discovery
    def discover_progress(completed: int, total: int) -> None:
        if config.show_progress and not config.verbose:
            print_progress_bar(completed, total, prefix='Discovery:', suffix='Complete', length=40)

    if config.skip_discovery:
        active_hosts = list(target_ips)
        logger.info(f"Skipping discovery, treating all {len(active_hosts)} targets as active")
    else:
        active_hosts = await discover_hosts_async(target_ips, progress_callback=discover_progress)

    if not active_hosts:
        logger.info("No active hosts found.")
        sys.exit(0)

    # Initialize results
    results: Dict = {}
    for ip in active_hosts:
        results[ip] = {'os': 'Unknown', 'ports': []}

    # Reverse DNS lookup
    with Spinner("Resolving hostnames..."):
        for ip in active_hosts:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                results[ip]['hostname'] = hostname
                logger.debug(f"Resolved {ip} -> {hostname}")
            except (socket.herror, OSError):
                results[ip]['hostname'] = ''

    # DNS records for target IPs
    if config.dns_enum:
        for ip in active_hosts:
            results[ip]['dns_records'] = dns_results.get(ip, {})

    # OS Fingerprinting
    if config.os_fingerprint:
        logger.info("OS fingerprinting...")
        with Spinner(f"Fingerprinting {len(active_hosts)} host(s)..."):
            os_tasks = [async_fingerprint_os(ip) for ip in active_hosts]
            os_results = await asyncio.gather(*os_tasks)
            for i, ip in enumerate(active_hosts):
                results[ip]['os'] = os_results[i]

    # Port Scanning
    if config.scan_type != 'ping' and ports_to_scan:
        for ip in active_hosts:
            def scan_progress(completed: int, total: int) -> None:
                if config.show_progress and not config.verbose:
                    print_progress_bar(completed, total, prefix=f'Scan {ip}:', suffix='Complete', length=40)

            open_ports = await scan_ports_async(
                ip, ports_to_scan,
                scan_type=config.scan_type,
                progress_callback=scan_progress
            )
            results[ip]['ports'] = open_ports

    # Web Technology Detection
    if config.tech_detect:
        from scan.tech_detect import detect_technologies
        logger.info("Detecting web technologies...")
        for ip in active_hosts:
            for p in results[ip].get('ports', []):
                banner = str(p.get('service', ''))
                if 'HTTP' in banner or p['port'] in [80, 443, 8080, 8443, 8000, 8888]:
                    techs = detect_technologies(banner)
                    if techs:
                        results[ip]['technologies'] = techs

    # Display Results
    print_results(results)

    # Traceroute in results
    if traceroute_results:
        for ip, hops in traceroute_results.items():
            if ip in results:
                results[ip]['traceroute'] = hops

    # Bruteforce
    if config.bruteforce:
        from scan.bruteforce import run_bruteforce
        await run_bruteforce(results)
        print_results(results)

    # Vulnerability Check
    vuln_results = {}
    if config.vuln_check:
        from scan.vuln_check import run_vuln_check
        vuln_results = run_vuln_check(results)
        for ip, vulns in vuln_results.items():
            if ip in results:
                results[ip]['vulnerabilities'] = vulns
        print_vuln_summary(vuln_results)

    # Summary
    duration = time.monotonic() - start_time
    total_open = sum(len(d.get('ports', [])) for d in results.values())
    print_scan_summary(
        total_targets=len(target_ips),
        active_hosts=len(active_hosts),
        ports_scanned=len(ports_to_scan),
        scan_type=config.scan_type,
        duration=duration,
    )

    # Export
    if config.output_file:
        export_results(results)


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()