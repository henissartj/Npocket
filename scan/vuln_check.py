import re
from typing import Dict, List, Optional, Tuple

from utils.logger import logger


VULN_SIGNATURES: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(r'OpenSSH[_-]?(\d+)\.(\d+)', re.I), 'SSH',
     'OpenSSH', 'CVE-2024-6387 regreSSHion / CVE-2023-38408 / CVE-2023-28531'),
    (re.compile(r'OpenSSH[_-]?([0-3])\.', re.I), 'SSH',
     'OpenSSH (<=3.x)', 'CVE-2006-4925 / CVE-2006-5794 (legacy)'),
    (re.compile(r'OpenSSH[_-]?4\.', re.I), 'SSH',
     'OpenSSH 4.x', 'CVE-2007-3102 (channel race)'),
    (re.compile(r'OpenSSH[_-]?5\.', re.I), 'SSH',
     'OpenSSH 5.x', 'Multiple CVEs (2008-2014)'),
    (re.compile(r'OpenSSH[_-]?7\.[0-6]', re.I), 'SSH',
     'OpenSSH <=7.6', 'CVE-2018-15473 (user enumeration)'),
    (re.compile(r'OpenSSH[_-]?6\.', re.I), 'SSH',
     'OpenSSH 6.x', 'Multiple CVEs (2012-2017)'),
    (re.compile(r'Apache(?:/(\d+\.\d+))?', re.I), 'HTTP',
     'Apache HTTPD', ''),
    (re.compile(r'Apache/1\.', re.I), 'HTTP', 'Apache 1.x',
     'CVE-2004-0493 / CVE-2005-3357 (EOL)'),
    (re.compile(r'Apache/2\.[0-2]\.', re.I), 'HTTP', 'Apache 2.0/2.2 (EOL)',
     'CVE-2017-9798 / CVE-2012-0021 / CVE-2011-3192 (Slowloris)'),
    (re.compile(r'Apache/2\.4\.(?:[0-9]|1[0-6])', re.I), 'HTTP', 'Apache 2.4.0-2.4.16',
     'CVE-2015-3183 / CVE-2014-6271 (HTTP2)'),
    (re.compile(r'nginx/(\d+)\.(\d+)', re.I), 'HTTP', 'Nginx', ''),
    (re.compile(r'nginx/1\.(?:[0-9]|1[0-9]|2[0-3])\.', re.I), 'HTTP',
     'Nginx <1.24', 'CVE-2021-23017 / CVE-2017-7529 / CVE-2021-3618'),
    (re.compile(r'nginx/0\.', re.I), 'HTTP', 'Nginx 0.x (EOL)',
     'CVE-2013-2028 / stack buffer overflow'),
    (re.compile(r'PHP/([45])\.', re.I), 'HTTP', 'PHP 4/5 (EOL)',
     'CVE-2024-4577 / Multiple RCE CVEs'),
    (re.compile(r'PHP/7\.[0-3]\.', re.I), 'HTTP', 'PHP 7.0-7.3 (EOL)',
     'CVE-2019-11043 / CVE-2018-5711'),
    (re.compile(r'PHP/8\.0\.', re.I), 'HTTP', 'PHP 8.0 (EOL)',
     'CVE-2023-3824 / EOL since Nov 2023'),
    (re.compile(r'Microsoft-IIS/6\.', re.I), 'HTTP', 'IIS 6.0 (EOL)',
     'CVE-2017-7269 / CVE-2008-4383'),
    (re.compile(r'Microsoft-IIS/7\.', re.I), 'HTTP', 'IIS 7.x (EOL)',
     'CVE-2010-1256 / CVE-2010-2731'),
    (re.compile(r'Microsoft-IIS/8\.0', re.I), 'HTTP', 'IIS 8.0',
     'CVE-2013-3868 / CVE-2014-4071'),
    (re.compile(r'vsFTPd[_-]?2\.[0-3]\.', re.I), 'FTP',
     'vsFTPd 2.x', 'CVE-2011-0762 / CVE-2015-1419'),
    (re.compile(r'vsFTPd[_-]?2\.0\.', re.I), 'FTP', 'vsFTPd 2.0.x',
     'CVE-2004-0763 (godspeed)'),
    (re.compile(r'ProFTPD[_-]?1\.3\.[0-5]', re.I), 'FTP', 'ProFTPD 1.3.0-1.3.5',
     'CVE-2011-4130 / CVE-2015-3306'),
    (re.compile(r'ProFTPD[_-]?1\.3\.[56]', re.I), 'FTP', 'ProFTPD 1.3.5-1.3.6',
     'CVE-2019-20807 / mod_copy RCE'),
    (re.compile(r'MySQL[_-]?5\.[0-6]\.', re.I), 'MySQL', 'MySQL 5.0-5.6 (EOL)',
     'CVE-2016-6662 / CVE-2016-6663'),
    (re.compile(r'MySQL[_-]?5\.7\.(?:[0-9]|1[0-9])', re.I), 'MySQL',
     'MySQL 5.7 < 5.7.20', 'CVE-2017-15378'),
    (re.compile(r'Redis[_-]?[0-3]\.', re.I), 'Redis', 'Redis <=3.x (EOL)',
     'CVE-2015-8080 / CVE-2016-10517'),
    (re.compile(r'Redis[_-]?4\.0\.', re.I), 'Redis', 'Redis 4.0.x',
     'CVE-2020-14147'),
    (re.compile(r'Redis[_-]?5\.0\.[0-4]', re.I), 'Redis', 'Redis 5.0.0-5.0.4',
     'CVE-2019-10193 / CVE-2019-10192'),
    (re.compile(r'OpenSSL/(\d+)\.(\d+)\.(\d+)', re.I), 'SSL/TLS', 'OpenSSL', ''),
    (re.compile(r'OpenSSL/[01]\.', re.I), 'SSL/TLS', 'OpenSSL <=1.x (EOL)',
     'CVE-2014-0160 (Heartbleed) / CVE-2014-0224 / Multiple CVEs'),
    (re.compile(r'OpenSSL/1\.0\.', re.I), 'SSL/TLS', 'OpenSSL 1.0.x (EOL)',
     'CVE-2014-0160 (Heartbleed) / CVE-2016-0800 / CVE-2016-2107'),
    (re.compile(r'OpenSSL/3\.0\.[0-6]', re.I), 'SSL/TLS', 'OpenSSL 3.0.0-3.0.6',
     'CVE-2022-3786 / CVE-2022-3602 / CVE-2022-2274'),
    (re.compile(r'OpenSSL/1\.1\.[01]', re.I), 'SSL/TLS', 'OpenSSL 1.1.0-1.1.1 (EOL)',
     'CVE-2023-0286 / CVE-2023-3817'),
    (re.compile(r'OpenSSH[_-]?9\.[0-4]', re.I), 'SSH', 'OpenSSH 9.0-9.4',
     'CVE-2023-38408 / CVE-2023-51385'),
    (re.compile(r'OpenSSH[_-]?8\.[0-9]', re.I), 'SSH', 'OpenSSH 8.x',
     'CVE-2021-41617 / CVE-2020-14145 / CVE-2019-6111'),
    (re.compile(r'vsFTPd[_-]?3\.0\.(?:[0-2])', re.I), 'FTP', 'vsFTPd 3.0.0-3.0.2',
     'CVE-2015-1419'),
    (re.compile(r'PostgreSQL[_-]?(?:9\.[0-6]|1[0-3]\.)', re.I), 'SQL', 'PostgreSQL (EOL version)',
     'CVE-2019-10164 / CVE-2018-1058 / CVE-2014-0062'),
    (re.compile(r'MongoDB[_-]?[0-3]\.', re.I), 'NoSQL', 'MongoDB <=3.x (EOL)',
     'CVE-2013-3966 / CVE-2015-2705'),
    (re.compile(r'WordPress[_-]?4\.', re.I), 'CMS', 'WordPress 4.x (EOL)',
     'CVE-2024-31234 / Multiple RCE / XSS / SQLi'),
    (re.compile(r'WordPress[_-]?[0-3]\.', re.I), 'CMS', 'WordPress <=3.x (EOL)',
     'CVE-2013-5738 / CVE-2014-9034 / CVE-2015-5623'),
    (re.compile(r'Drupal[_-]?7\.', re.I), 'CMS', 'Drupal 7 (EOL)',
     'CVE-2019-6340 / CVE-2018-7600 (Drupalgeddon 2)'),
    (re.compile(r'Drupal[_-]?8\.', re.I), 'CMS', 'Drupal 8 (EOL)',
     'CVE-2019-6339 / CVE-2018-7602'),
]


def check_vulnerabilities(service_banner: str, port: int, service_name: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []

    for pattern, category, name, cve_info in VULN_SIGNATURES:
        if pattern.search(service_banner):
            finding = {
                'category': category,
                'service': name,
                'cve': cve_info if cve_info else 'Check for relevant CVEs',
                'banner_match': service_banner[:80],
            }
            findings.append(finding)
            logger.warning(f"[!] Potential vulnerability: {name} ({cve_info})")

    return findings


def check_port_vulnerabilities(port: int, protocol: str) -> List[str]:
    warnings: List[str] = []

    exposed_services = {
        21: 'FTP (cleartext credentials)',
        23: 'Telnet (unencrypted)',
        25: 'SMTP (spam relay risk)',
        53: 'DNS (zone transfer risk)',
        110: 'POP3 (cleartext credentials)',
        135: 'MSRPC (info leak)',
        139: 'NetBIOS (info leak)',
        143: 'IMAP (cleartext credentials)',
        389: 'LDAP (cleartext)',
        445: 'SMB (EternalBlue risk)',
        512: 'reXec (unencrypted)',
        513: 'Rlogin (unencrypted)',
        514: 'RSH (unencrypted)',
        1080: 'SOCKS proxy (open proxy risk)',
        1433: 'MSSQL (bruteforce risk)',
        1521: 'Oracle (default creds)',
        2049: 'NFS (unsecured shares)',
        2375: 'Docker (unauthenticated API)',
        3128: 'Squid (open proxy)',
        3306: 'MySQL (remote access)',
        3389: 'RDP (BlueKeep risk if <= Win7)',
        5432: 'PostgreSQL (remote access)',
        5900: 'VNC (auth risk)',
        5984: 'CouchDB (open API)',
        6379: 'Redis (unauthenticated risk)',
        9200: 'Elasticsearch (open API)',
        11211: 'Memcached (DDoS amplification)',
        27017: 'MongoDB (unauthenticated access)',
    }

    if port in exposed_services:
        warnings.append(f"Port {port} ({exposed_services[port]})")

    return warnings


def run_vuln_check(results: Dict) -> Dict:
    logger.info("Running vulnerability checks...")
    vuln_results: Dict = {}

    for ip, data in results.items():
        host_vulns: List[Dict] = []
        for port_info in data.get('ports', []):
            if port_info['state'] != 'open':
                continue

            service_banner = str(port_info.get('service', ''))
            port = port_info['port']

            port_warnings = check_port_vulnerabilities(port, port_info['protocol'])
            for w in port_warnings:
                host_vulns.append({
                    'type': 'exposed_service',
                    'port': port,
                    'detail': w,
                    'severity': 'medium',
                })
                logger.warning(f"[{ip}] Exposed service: {w}")

            if service_banner and service_banner != 'None':
                cvulns = check_vulnerabilities(service_banner, port, port_info.get('service', ''))
                for cv in cvulns:
                    cv['port'] = port
                    host_vulns.append(cv)

        if host_vulns:
            vuln_results[ip] = host_vulns

    total_vulns = sum(len(v) for v in vuln_results.values())
    logger.info(f"Vulnerability check complete: {total_vulns} potential issue(s) found across {len(vuln_results)} host(s)")
    return vuln_results