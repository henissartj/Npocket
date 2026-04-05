import argparse
import sys
import logging
import os
import asyncio
import platform

# Add parent directory to sys.path if running as script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logger import setup_logger, logger
from utils.config import config
from utils.ui import print_progress_bar, Colors
from parse.parser import parse_targets, parse_ports
from scan.discover import discover_hosts_async
from scan.port_scan import scan_ports_async
from scan.os_fingerprint import async_fingerprint_os
from report.formatter import print_banner, print_results
from report.exporter import export_results

class NpocketHelpFormatter(argparse.RawTextHelpFormatter):
    """Custom formatter to improve help menu spacing."""
    def _format_action(self, action):
        parts = super()._format_action(action)
        if action.help == argparse.SUPPRESS:
            return parts
        return parts + '\n'

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}{Colors.OKGREEN}Network Exploration & Security Auditing Tool{Colors.ENDC}",
        usage=f"{Colors.OKCYAN}npocket [targets] [options]{Colors.ENDC}",
        formatter_class=lambda prog: NpocketHelpFormatter(prog, max_help_position=40, width=100),
        add_help=False
    )
    
    # General
    gen_group = parser.add_argument_group(f'{Colors.BOLD}{Colors.HEADER}📌 General Options{Colors.ENDC}')
    gen_group.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this beautiful help message and exit')
    
    # Target specification
    target_group = parser.add_argument_group(f'{Colors.BOLD}{Colors.OKBLUE}🎯 Target Specification{Colors.ENDC}')
    target_group.add_argument('targets', nargs='?', help='Target IP, Domain, CIDR, or Range\nExamples: 192.168.1.1, 10.0.0.0/24, example.com')
    target_group.add_argument('-sD', '--subdomains', action='store_true', help='Enumerate subdomains and bruteforce DNS (for domain targets)')
    
    # Port specification
    port_group = parser.add_argument_group(f'{Colors.BOLD}{Colors.OKBLUE}🚪 Port Specification{Colors.ENDC}')
    port_group.add_argument('-p', '--ports', default='top100', help='Ports to scan (default: top100)\nExamples: 80,443,1000-2000, all, top100')
    
    # Scan Types
    scan_group = parser.add_argument_group(f'{Colors.BOLD}{Colors.OKBLUE}🔍 Scan Techniques{Colors.ENDC}')
    scan_group.add_argument('-sS', '--tcp', action='store_true', help='TCP Connect Scan (default, ultra-fast)')
    scan_group.add_argument('-sU', '--udp', action='store_true', help='UDP Scan (requires elevated privileges on some systems)')
    scan_group.add_argument('-sn', '--ping-scan', action='store_true', help='Ping Scan only (disables port scanning)')
    scan_group.add_argument('-sV', '--service', action='store_true', help='Service & Version detection (includes Web Info Grabber)')
    scan_group.add_argument('-O', '--os-fingerprint', action='store_true', help='Enable heuristic OS fingerprinting')
    scan_group.add_argument('-B', '--bruteforce', action='store_true', help='Basic intelligent bruteforce on discovered services (e.g. FTP)')
    
    # Performance & Timing
    perf_group = parser.add_argument_group(f'{Colors.BOLD}{Colors.OKBLUE}⚡ Performance & Timing{Colors.ENDC}')
    perf_group.add_argument('-T', '--timeout', type=float, default=1.5, help='Connection timeout in seconds (default: 1.5)')
    perf_group.add_argument('-c', '--concurrency', type=int, default=500, help='Number of concurrent async tasks (default: 500)')
    perf_group.add_argument('--smart', action='store_true', help='Smart adaptive timing (dynamically adjusts timeouts based on latency)')
    
    # Output
    out_group = parser.add_argument_group(f'{Colors.BOLD}{Colors.OKBLUE}📊 Output & Display{Colors.ENDC}')
    out_group.add_argument('-v', '--verbose', action='store_true', help='Increase verbosity (debug mode)')
    out_group.add_argument('--no-progress', action='store_true', help='Disable the sleek progress bar')
    out_group.add_argument('-oJ', '--output-json', help='Export results to a JSON file', metavar='FILE')
    out_group.add_argument('-oC', '--output-csv', help='Export results to a CSV file', metavar='FILE')
    out_group.add_argument('-oM', '--output-md', help='Export results to a Markdown report', metavar='FILE')
    out_group.add_argument('-oH', '--output-html', help='Export results to an Interactive HTML Dashboard', metavar='FILE')
    
    # Custom help display handling
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_banner()
        parser.print_help()
        sys.exit(0)
        
    return parser.parse_args()

async def main_async():
    args = parse_args()
    print_banner()
    
    if not args.targets:
        logger.error("No targets specified. Use -h for help.")
        sys.exit(1)
        
    # Update global config
    config.timeout = args.timeout
    config.concurrency = args.concurrency
    config.verbose = args.verbose
    config.service_detection = args.service
    config.show_progress = not args.no_progress
    config.adaptive_timing = args.smart
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    if args.udp:
        config.scan_type = 'udp'
    else:
        config.scan_type = 'tcp'
        
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
        
    # Parse inputs
    logger.info("Parsing targets and ports...")
    target_ips = parse_targets(args.targets)
    ports_to_scan = parse_ports(args.ports)
    
    if args.subdomains:
        from scan.subdomain import enumerate_subdomains
        import re
        domain_targets = [t for t in args.targets.split(',') if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', t.strip())]
        for domain in domain_targets:
            discovered = await enumerate_subdomains(domain.strip())
            for sub, ip in discovered:
                if ip not in target_ips:
                    target_ips.append(ip)
    
    if not target_ips:
        logger.error("No valid targets found.")
        sys.exit(1)
        
    config.targets = target_ips
    config.ports = ports_to_scan
    
    logger.info(f"Targets to scan: {len(target_ips)}")
    if not args.ping_scan:
        logger.info(f"Ports to scan per host: {len(ports_to_scan)}")
        
    # Phase 1: Host Discovery
    def discover_progress(completed, total):
        if config.show_progress and not config.verbose:
            print_progress_bar(completed, total, prefix='Discovery:', suffix='Complete', length=40)
            
    active_hosts = await discover_hosts_async(target_ips, progress_callback=discover_progress)
    
    if not active_hosts:
        logger.info("No active hosts found. Exiting.")
        sys.exit(0)
        
    # Store final results
    results = {}
    for ip in active_hosts:
        results[ip] = {
            'os': 'Unknown',
            'ports': []
        }
        
    # Phase 2: OS Fingerprinting (if requested)
    if args.os_fingerprint:
        logger.info("Starting OS fingerprinting...")
        
        # We can do this concurrently for all active hosts
        os_tasks = [async_fingerprint_os(ip) for ip in active_hosts]
        os_results = await asyncio.gather(*os_tasks)
        
        for i, ip in enumerate(active_hosts):
            results[ip]['os'] = os_results[i]
            
    # Phase 3: Port Scanning
    if not args.ping_scan:
        for ip in active_hosts:
            def scan_progress(completed, total):
                if config.show_progress and not config.verbose:
                    print_progress_bar(completed, total, prefix=f'Scan {ip}:', suffix='Complete', length=40)
                    
            open_ports = await scan_ports_async(ip, ports_to_scan, scan_type=config.scan_type, progress_callback=scan_progress)
            results[ip]['ports'] = open_ports
            
    # Display Results
    print_results(results)
    
    # Run bruteforce if requested
    if args.bruteforce:
        from scan.bruteforce import run_bruteforce
        await run_bruteforce(results)
        # Re-print results with bruteforce info
        print_results(results)
        
    # Export Results
    if config.output_file:
        export_results(results)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
