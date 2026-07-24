import asyncio
import socket
from typing import Dict, List, Optional, Tuple

from utils.logger import logger
from utils.config import config


COMMON_SUBDOMAINS: List[str] = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "webdisk", "server", "cpanel", "whm", "autodiscover", "autoconfig",
    "m", "imap", "test", "ns2", "blog", "dev", "api", "admin", "vpn",
    "cloud", "firewall", "staging", "secure", "gw", "portal", "shop",
    "forum", "wiki", "support", "help", "status", "download", "docs",
    "kb", "faq", "community", "news", "store", "demo", "app",
    "mobile", "remote", "office", "intranet", "exchange", "owa", "vdi",
    "gitlab", "jenkins", "jira", "confluence", "nexus", "artifactory",
    "grafana", "prometheus", "kibana", "elastic", "logstash", "splunk",
    "zabbix", "nagios", "cacti", "munin", "observium", "librenms",
    "dashboard", "monitor", "monitoring", "metrics", "stats", "analytics",
    "panel", "manager", "management", "console", "control", "adminer",
    "phpmyadmin", "phpadmin", "pma", "mysqladmin", "pgsqladmin",
    "direct", "directadmin", "vesta", "vestacp", "sentora", "centoswebpanel",
    "rest", "graphql", "swagger", "api-docs", "apidocs",
    "stage", "stg", "prod", "production", "development", "coding",
    "documentation", "readme", "changelog", "release",
    "email", "outlook", "zimbra", "roundcube", "squirrelmail",
    "radius", "ldap", "adfs", "sso", "oauth", "auth", "login", "signin",
    "register", "signup", "account", "accounts", "profile", "profiles",
    "cdn", "static", "assets", "img", "css", "js", "uploads",
    "video", "audio", "media", "stream", "live", "tv", "radio",
    "res", "resources", "files", "file",
    "updates", "update", "patch", "hotfix", "security", "ssl",
    "mta", "mx", "ns3", "ns4", "dns1", "dns2",
    "gateway", "router", "switch", "proxy", "squid", "nginx",
    "waf", "ids", "ips", "siem", "soar", "honeypot",
    "docker", "k8s", "kubernetes", "swarm", "rancher", "harbor",
    "registry", "repo", "repository", "dockerhub", "docker-registry",
    "backup", "bak", "backups", "dump", "snapshot", "archive",
    "www2", "www3", "www4", "en", "fr", "de", "es", "it", "pt", "ru",
    "jp", "cn", "br", "nl", "pl", "au", "ca", "uk", "in", "kr",
]


async def resolve_subdomain(subdomain: str, domain: str, sem: asyncio.Semaphore) -> Tuple[Optional[str], Optional[str]]:
    target = f"{subdomain}.{domain}"
    loop = asyncio.get_event_loop()
    try:
        async with sem:
            result = await loop.run_in_executor(None, socket.gethostbyname, target)
            return target, result
    except (socket.gaierror, OSError):
        return None, None


async def enumerate_subdomains(domain: str) -> List[Tuple[str, str]]:
    logger.info(f"Enumerating subdomains for {domain} ({len(COMMON_SUBDOMAINS)} entries)...")
    sem = asyncio.Semaphore(min(config.concurrency, 100))
    tasks = [resolve_subdomain(sub, domain, sem) for sub in COMMON_SUBDOMAINS]

    discovered: List[Tuple[str, str]] = []

    for coro in asyncio.as_completed(tasks):
        target, ip = await coro
        if target and ip:
            discovered.append((target, ip))
            logger.info(f"[+] {target} -> {ip}")

    logger.info(f"Found {len(discovered)} subdomains for {domain}")
    return discovered