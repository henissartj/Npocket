import json
import csv
import time
from typing import Dict, List, Optional

from utils.logger import logger
from utils.config import config
from scan.tech_detect import format_tech_summary


def export_json(results: Dict, filename: str) -> None:
    try:
        report = {
            'tool': 'Npocket v2.0.0',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'summary': {
                'total_hosts': len(results),
                'total_open_ports': sum(len(d.get('ports', [])) for d in results.values()),
            },
            'hosts': results,
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Exported JSON -> {filename}")
    except Exception as e:
        logger.error(f"JSON export error: {e}")


def export_csv(results: Dict, filename: str) -> None:
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Hostname', 'OS', 'Port', 'Protocol', 'State', 'Service', 'Bruteforce', 'Vulnerabilities'])
            for ip, data in results.items():
                os_guess = data.get('os', 'Unknown')
                hostname = data.get('hostname', '')
                for p in data.get('ports', []):
                    vulns = '; '.join(
                        v.get('cve', v.get('detail', ''))
                        for v in p.get('vulnerabilities', [])
                    ) if p.get('vulnerabilities') else ''
                    writer.writerow([
                        ip, hostname, os_guess,
                        p.get('port', ''),
                        p.get('protocol', ''),
                        p.get('state', ''),
                        str(p.get('service', '') or '-')[:60],
                        str(p.get('bruteforce', '') or '')[:40],
                        vulns[:100],
                    ])
        logger.info(f"Exported CSV -> {filename}")
    except Exception as e:
        logger.error(f"CSV export error: {e}")


def export_markdown(results: Dict, filename: str) -> None:
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f'# Npocket Scan Report\n\n')
            f.write(f'**Generated:** {time.strftime("%Y-%m-%d %H:%M:%S")}\n\n')
            f.write(f'**Hosts scanned:** {len(results)}\n')
            total_ports = sum(len(d.get('ports', [])) for d in results.values())
            f.write(f'**Open ports found:** {total_ports}\n\n')
            f.write('---\n\n')

            for ip, data in results.items():
                os_guess = data.get('os', 'Unknown')
                hostname = data.get('hostname', '')
                vulns = data.get('vulnerabilities', [])
                techs = data.get('technologies', {})
                traceroute_data = data.get('traceroute', [])
                dns_records = data.get('dns_records', {})

                f.write(f'## Host: {ip}\n\n')
                if hostname:
                    f.write(f'- **Hostname:** {hostname}\n')
                f.write(f'- **OS Guess:** {os_guess}\n')
                if techs:
                    f.write(f'- **Web Technologies:** {format_tech_summary(techs)}\n')

                ports = data.get('ports', [])
                if ports:
                    f.write('\n| Port | Protocol | State | Service | Bruteforce |\n')
                    f.write('|------|----------|-------|---------|------------|\n')
                    for p in ports:
                        brute = p.get('bruteforce', '') or '-'
                        svc = str(p.get('service', '') or '-')[:50]
                        f.write(f"| {p.get('port', '')} | {p.get('protocol', '')} | {p.get('state', '')} | {svc} | {brute} |\n")
                else:
                    f.write('\n*No open ports found.*\n')

                if vulns:
                    f.write('\n### Vulnerabilities\n\n')
                    for v in vulns:
                        cve = v.get('cve', v.get('detail', ''))
                        f.write(f'- [{v.get("service", "?")}] {cve}\n')

                if traceroute_data:
                    f.write('\n### Traceroute\n\n')
                    f.write('| Hop | IP |\n|-----|----|\n')
                    for hop_num, hop_ip, rtt in traceroute_data[:15]:
                        f.write(f'| {hop_num} | {hop_ip} |\n')

                if dns_records:
                    f.write('\n### DNS Records\n\n')
                    for rtype, records in dns_records.items():
                        for rec in records[:5]:
                            f.write(f'- **{rtype}:** {rec}\n')

                f.write('\n---\n\n')

        logger.info(f"Exported Markdown -> {filename}")
    except Exception as e:
        logger.error(f"Markdown export error: {e}")


def export_html(results: Dict, filename: str) -> None:
    try:
        total_hosts = len(results)
        total_open = sum(len(d.get('ports', [])) for d in results.values())
        total_vulns = sum(
            len(d.get('vulnerabilities', [])) for d in results.values()
        )

        host_cards = ""
        for ip, data in results.items():
            os_guess = data.get('os', 'Unknown')
            hostname = data.get('hostname', '')
            vulns = data.get('vulnerabilities', [])
            techs = data.get('technologies', {})
            dns_records = data.get('dns_records', {})
            traceroute_data = data.get('traceroute', [])
            ports = data.get('ports', [])

            port_rows = ""
            for p in ports:
                state_class = f"state-{p.get('state', '').lower().replace('|', '-')}"
                svc = str(p.get('service', ''))[:60] if p.get('service') else '-'
                brute = p.get('bruteforce', '')
                brute_html = f'<span class="brute-success">{brute}</span>' if brute and 'SUCCESS' in str(brute) else ''
                port_rows += f"""
                    <tr>
                        <td>{p.get('port', '')}/{p.get('protocol', '')}</td>
                        <td class="{state_class}">{p.get('state', '')}</td>
                        <td>{svc}</td>
                        <td>{brute_html}</td>
                    </tr>"""

            vuln_html = ""
            if vulns:
                vuln_items = "".join(
                    f'<li><strong>[{v.get("port", "?")}] {v.get("service", "")}:</strong> {v.get("cve", v.get("detail", ""))}</li>'
                    for v in vulns[:8]
                )
                vuln_html = f'<div class="vulns"><h3>Vulnerabilities ({len(vulns)})</h3><ul>{vuln_items}</ul></div>'

            tech_html = ""
            if techs:
                from scan.tech_detect import format_tech_summary
                tech_html = f'<div class="techs">Technologies: {format_tech_summary(techs)}</div>'

            dns_html = ""
            if dns_records:
                items = ""
                for rtype, records in dns_records.items():
                    for rec in records[:5]:
                        items += f'<li><strong>{rtype}:</strong> {rec}</li>'
                dns_html = f'<details><summary>DNS Records</summary><ul>{items}</ul></details>'

            trace_html = ""
            if traceroute_data:
                items = "".join(f'<li>Hop {n}: {ip}</li>' for n, ip, rtt in traceroute_data[:15])
                trace_html = f'<details><summary>Traceroute ({len(traceroute_data)} hops)</summary><ol>{items}</ol></details>'

            host_cards += f"""
            <div class="host-card">
                <div class="host-header">
                    <div class="host-ip">{ip}</div>
                    <div class="os-guess">OS: {os_guess}</div>
                </div>
                {f'<div class="hostname">Hostname: {hostname}</div>' if hostname else ''}
                {tech_html}
                {vuln_html}
                {dns_html}
                {trace_html}
                <table>
                    <thead><tr><th>Port/Proto</th><th>State</th><th>Service</th><th>Bruteforce</th></tr></thead>
                    <tbody>{port_rows if port_rows else '<tr><td colspan="4" class="no-results">No open ports found</td></tr>'}</tbody>
                </table>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Npocket Scan Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }}
        h1 {{ color: #58a6ff; text-align: center; font-size: 2em; margin-bottom: 5px; }}
        .subtitle {{ text-align: center; color: #8b949e; margin-bottom: 20px; }}
        .summary {{ display: flex; justify-content: center; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
        .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px 25px; text-align: center; min-width: 120px; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: 0.85em; color: #8b949e; }}
        .stat.warning .stat-value {{ color: #f0883e; }}
        .stat.danger .stat-value {{ color: #f85149; }}
        .host-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .host-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; padding-bottom: 10px; margin-bottom: 15px; flex-wrap: wrap; }}
        .host-ip {{ font-size: 1.3em; font-weight: bold; color: #d2a8ff; }}
        .hostname {{ color: #8b949e; font-size: 0.9em; margin-bottom: 10px; }}
        .os-guess {{ font-size: 0.9em; background: #21262d; padding: 4px 10px; border-radius: 4px; color: #7ee787; }}
        .techs {{ color: #79c0ff; font-size: 0.9em; margin-bottom: 10px; }}
        .vulns {{ background: #3d1214; border: 1px solid #f85149; border-radius: 6px; padding: 10px 15px; margin-bottom: 10px; }}
        .vulns h3 {{ color: #f85149; font-size: 0.95em; margin-bottom: 5px; }}
        .vulns ul {{ padding-left: 20px; }}
        .vulns li {{ color: #f0883e; font-size: 0.85em; margin: 3px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
        th {{ background: #21262d; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.8em; }}
        tr:hover td {{ background: #1c2128; }}
        .state-open {{ color: #3fb950; font-weight: bold; }}
        .state-filtered {{ color: #d29922; font-weight: bold; }}
        .state-closed {{ color: #f85149; }}
        .state-open\\|filtered {{ color: #d29922; }}
        .no-results {{ color: #8b949e; text-align: center; font-style: italic; }}
        .brute-success {{ color: #f85149; font-weight: bold; }}
        details {{ margin: 10px 0; }}
        summary {{ cursor: pointer; color: #58a6ff; font-weight: 600; }}
        summary:hover {{ color: #79c0ff; }}
        details ul, details ol {{ padding-left: 20px; margin: 5px 0; color: #8b949e; font-size: 0.9em; }}
        .footer {{ text-align: center; color: #484f58; font-size: 0.8em; margin-top: 30px; }}
        @media (max-width: 600px) {{ .summary {{ flex-direction: column; align-items: center; }} }}
    </style>
</head>
<body>
    <h1>Npocket Scan Dashboard</h1>
    <p class="subtitle">Network Exploration & Security Auditing &mdash; {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    <div class="summary">
        <div class="stat"><div class="stat-value">{total_hosts}</div><div class="stat-label">Hosts</div></div>
        <div class="stat"><div class="stat-value">{total_open}</div><div class="stat-label">Open Ports</div></div>
        <div class="stat {'danger' if total_vulns > 0 else ''}"><div class="stat-value">{total_vulns}</div><div class="stat-label">Vulnerabilities</div></div>
    </div>
    {host_cards}
    <div class="footer">Generated by Npocket v2.0.0 &mdash; github.com/urbanyl/npocket</div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        logger.info(f"Exported HTML -> {filename}")
    except Exception as e:
        logger.error(f"HTML export error: {e}")


def export_all_formats(results: Dict, base_name: str) -> None:
    export_json(results, f"{base_name}.json")
    export_csv(results, f"{base_name}.csv")
    export_markdown(results, f"{base_name}.md")
    export_html(results, f"{base_name}.html")


def export_results(results: Dict) -> None:
    if not config.output_file:
        return
    fmt = config.output_format.lower()
    if fmt == 'json':
        export_json(results, config.output_file)
    elif fmt == 'csv':
        export_csv(results, config.output_file)
    elif fmt == 'md':
        export_markdown(results, config.output_file)
    elif fmt == 'html':
        export_html(results, config.output_file)
    elif fmt == 'all':
        base = config.output_file.rsplit('.', 1)[0] if '.' in config.output_file else config.output_file
        export_all_formats(results, base)
    else:
        logger.warning(f"Unsupported format: {fmt}")