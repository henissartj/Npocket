import re
from typing import Dict, List, Optional

from utils.logger import logger


TECHNOLOGY_PATTERNS: List[tuple] = [
    (re.compile(r'server:\s*nginx/?([\d.]+)?', re.I), 'Nginx'),
    (re.compile(r'server:\s*Apache(?:/([\d.]+))?', re.I), 'Apache HTTPD'),
    (re.compile(r'server:\s*IIS?(?:/([\d.]+))?', re.I), 'Microsoft IIS'),
    (re.compile(r'server:\s*lighttpd(?:/([\d.]+))?', re.I), 'Lighttpd'),
    (re.compile(r'server:\s*Caddy(?:/([\d.]+))?', re.I), 'Caddy'),
    (re.compile(r'server:\s*OpenResty(?:/([\d.]+))?', re.I), 'OpenResty'),
    (re.compile(r'server:\s*cloudflare', re.I), 'Cloudflare'),
    (re.compile(r'x-powered-by:\s*PHP(?:/([\d.]+))?', re.I), 'PHP'),
    (re.compile(r'x-powered-by:\s*ASP\.NET', re.I), 'ASP.NET'),
    (re.compile(r'x-powered-by:\s*Express', re.I), 'Express.js'),
    (re.compile(r'x-powered-by:\s*Rails', re.I), 'Ruby on Rails'),
    (re.compile(r'x-powered-by:\s*Django', re.I), 'Django'),
    (re.compile(r'x-powered-by:\s*Laravel', re.I), 'Laravel'),
    (re.compile(r'x-generator:\s*WordPress(?:/([\d.]+))?', re.I), 'WordPress'),
    (re.compile(r'x-generator:\s*Drupal(?:/([\d.]+))?', re.I), 'Drupal'),
    (re.compile(r'x-generator:\s*Joomla!?(?:/([\d.]+))?', re.I), 'Joomla'),
    (re.compile(r'x-drupal-cache', re.I), 'Drupal'),
    (re.compile(r'x-joomla-cache', re.I), 'Joomla'),
    (re.compile(r'wp-content', re.I), 'WordPress'),
    (re.compile(r'wp-includes', re.I), 'WordPress'),
    (re.compile(r'x-magento', re.I), 'Magento'),
    (re.compile(r'x-varnish', re.I), 'Varnish Cache'),
    (re.compile(r'via:\s*1\.1\s+varnish', re.I), 'Varnish Cache'),
    (re.compile(r'x-cache:\s*HIT', re.I), 'Reverse Proxy Cache'),
    (re.compile(r'cf-ray', re.I), 'Cloudflare'),
    (re.compile(r'x-amz-(?:rid|request-id)', re.I), 'Amazon Web Services'),
    (re.compile(r'server:\s*gunicorn', re.I), 'Gunicorn'),
    (re.compile(r'server:\s*uWSGI', re.I), 'uWSGI'),
    (re.compile(r'set-cookie:\s*PHPSESSID', re.I), 'PHP'),
    (re.compile(r'set-cookie:\s*ASPNET_SessionId', re.I), 'ASP.NET'),
    (re.compile(r'set-cookie:\s*JSESSIONID', re.I), 'Java/J2EE'),
    (re.compile(r'set-cookie:\s*connect\.sid', re.I), 'Express.js'),
    (re.compile(r'set-cookie:\s*laravel_session', re.I), 'Laravel'),
    (re.compile(r'set-cookie:\s*wordpress_logged_in', re.I), 'WordPress'),
    (re.compile(r'set-cookie:\s*wp-settings', re.I), 'WordPress'),
    (re.compile(r'x-content-type-options:\s*nosniff', re.I), 'Security Headers'),
    (re.compile(r'strict-transport-security', re.I), 'HSTS'),
    (re.compile(r'content-security-policy', re.I), 'CSP'),
    (re.compile(r'x-frame-options:\s*DENY', re.I), 'Security Headers'),
    (re.compile(r'x-xss-protection', re.I), 'Security Headers'),
]


def detect_technologies(headers: str, body: str = '') -> Dict[str, str]:
    detected: Dict[str, str] = {}
    combined = headers + '\n' + body[:5000]

    for pattern, tech_name in TECHNOLOGY_PATTERNS:
        match = pattern.search(combined)
        if match:
            version = match.group(1) if match.lastindex and match.group(1) else ''
            if version:
                detected[tech_name] = version
            elif tech_name not in detected:
                detected[tech_name] = ''

    return detected


def format_tech_summary(technologies: Dict[str, str]) -> str:
    if not technologies:
        return ""
    parts = [f"{name} {ver}" if ver else name for name, ver in sorted(technologies.items())]
    return ", ".join(parts[:8])