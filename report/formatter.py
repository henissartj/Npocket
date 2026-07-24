import time
from typing import Dict, List, Optional

from utils.ui import Colors, format_status, get_terminal_width, separator, print_header


def print_banner() -> None:
    banner = f"""{Colors.OKCYAN}{Colors.BOLD}
    _   __                 __        __
   / | / /___  ____  _____/ /_____  / /_
  /  |/ / __ \\/ __ \\/ ___/ //_/ _ \\/ __/
 / /|  / /_/ / /_/ / /__/ ,< /  __/ /_
/_/ |_/ .___/\\____/\\___/_/|_|\\___/\\__/
     /_/
    {Colors.ENDC}"""
    print(banner)
    print(f"{Colors.OKGREEN}The Modern Network Scanner  v2.0.0{Colors.ENDC}")
    print(f"{Colors.DIM}Network Exploration & Security Auditing{Colors.ENDC}\n")


def print_scan_summary(
    total_targets: int,
    active_hosts: int,
    ports_scanned: int,
    scan_type: str,
    duration: float
) -> None:
    print(f"\n{Colors.OKBLUE}{'=' * get_terminal_width()}{Colors.ENDC}")
    print(f"{Colors.BOLD}Npocket Scan Summary{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'=' * get_terminal_width()}{Colors.ENDC}")

    summary_items = [
        ("Targets", str(total_targets)),
        ("Active Hosts", str(active_hosts)),
        ("Ports per Host", str(ports_scanned)),
        ("Scan Type", scan_type.upper()),
        ("Duration", f"{duration:.1f}s"),
    ]

    for label, value in summary_items:
        print(f"  {Colors.BOLD}{label}:{Colors.ENDC} {Colors.OKGREEN}{value}{Colors.ENDC}")


def print_results(results: Dict) -> None:
    total_open = sum(len(d.get('ports', [])) for d in results.values())
    print(f"\n{Colors.OKBLUE}{'=' * get_terminal_width()}{Colors.ENDC}")
    print(f"{Colors.BOLD}Npocket Scan Report — {len(results)} host(s), {total_open} open port(s){Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'=' * get_terminal_width()}{Colors.ENDC}")

    for i, (ip, data) in enumerate(results.items()):
        os_guess = data.get('os', 'Unknown')
        hostname = data.get('hostname', '')
        vulns = data.get('vulnerabilities', [])
        dns_records = data.get('dns_records', {})
        traceroute_data = data.get('traceroute', [])
        technologies = data.get('technologies', {})

        print(f"\n{Colors.BOLD}{Colors.OKCYAN}[{i+1}] Host: {ip}{Colors.ENDC}")
        if hostname:
            print(f"     Hostname: {Colors.ITALIC}{hostname}{Colors.ENDC}")

        if os_guess != 'Unknown':
            print(f"     OS: {Colors.OKGREEN}{os_guess}{Colors.ENDC}")
        else:
            print(f"     OS: {Colors.WARNING}Unknown{Colors.ENDC}")

        if technologies:
            from scan.tech_detect import format_tech_summary
            print(f"     Web Tech: {Colors.OKGREEN}{format_tech_summary(technologies)}{Colors.ENDC}")

        ports = data.get('ports', [])
        if ports:
            print(f"\n     {Colors.BOLD}{'PORT':<10} {'STATE':<15} {'SERVICE'}{Colors.ENDC}")
            print(f"     {'-' * 60}")
            for p in ports:
                port_proto = f"{p['port']}/{p['protocol']}"
                colored_state = format_status(p['state'])
                service = str(p.get('service', 'unknown')) if p.get('service') else 'unknown'
                service = (service[:45] + '...') if len(service) > 48 else service
                state_len = len(p['state'])
                padding = 15 - state_len
                line = f"     {port_proto:<10} {colored_state}{' ' * padding} {service}"

                brute = p.get('bruteforce')
                if brute:
                    if "SUCCESS" in str(brute):
                        line += f" {Colors.FAIL}{Colors.BOLD}[{brute}]{Colors.ENDC}"
                    else:
                        line += f" {Colors.WARNING}[BF: {brute}]{Colors.ENDC}"

                if p.get('vulnerabilities'):
                    line += f" {Colors.FAIL}[VULN]{Colors.ENDC}"

                print(line)

            if vulns:
                print(f"\n     {Colors.FAIL}{Colors.BOLD}Vulnerabilities:{Colors.ENDC}")
                for v in vulns[:5]:
                    detail = v.get('detail', v.get('cve', ''))
                    print(f"       {Colors.FAIL}*{Colors.ENDC} [Port {v.get('port', '?')}] {v.get('service', '')}: {detail[:80]}")

            if traceroute_data:
                print(f"\n     {Colors.OKCYAN}Traceroute:{Colors.ENDC}")
                for hop_num, hop_ip, rtt in traceroute_data[:10]:
                    print(f"       {hop_num}. {hop_ip}")

        else:
            print(f"\n     {Colors.WARNING}No open ports found.{Colors.ENDC}")

        if dns_records:
            print(f"\n     {Colors.OKCYAN}DNS Records:{Colors.ENDC}")
            for rtype, records in dns_records.items():
                for rec in records[:3]:
                    print(f"       {rtype}: {rec}")
                if len(records) > 3:
                    print(f"       ... and {len(records) - 3} more")

    print(f"\n{Colors.OKBLUE}{'=' * get_terminal_width()}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Scan completed.{Colors.ENDC}")
    print(f"{Colors.DIM}Report generated at {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")


def print_vuln_summary(vuln_results: Dict) -> None:
    if not vuln_results:
        return
    print(f"\n{Colors.FAIL}{Colors.BOLD}{'=' * get_terminal_width()}{Colors.ENDC}")
    print(f"{Colors.FAIL}{Colors.BOLD}SECURITY ALERTS{Colors.ENDC}")
    print(f"{Colors.FAIL}{Colors.BOLD}{'=' * get_terminal_width()}{Colors.ENDC}")
    for ip, vulns in vuln_results.items():
        print(f"\n  {Colors.FAIL}[!] {ip}{Colors.ENDC} — {len(vulns)} issue(s)")
        for v in vulns[:3]:
            cve_str = v.get('cve', v.get('detail', ''))
            print(f"     {Colors.WARNING}*{Colors.ENDC} {v.get('service', '')}: {cve_str[:100]}")
        if len(vulns) > 3:
            print(f"     {Colors.DIM}... and {len(vulns) - 3} more{Colors.ENDC}")


def print_discovered_subdomains(subdomains: list) -> None:
    if not subdomains:
        return
    print(f"\n{Colors.OKCYAN}[+] Discovered Subdomains{Colors.ENDC}")
    for target, ip in subdomains:
        print(f"  {Colors.OKGREEN}{target}{Colors.ENDC} -> {ip}")