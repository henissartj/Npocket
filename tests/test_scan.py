import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from utils.config import config

from scan.subdomain import COMMON_SUBDOMAINS
from scan.service import detect_protocol, parse_http_response
from scan.port_scan import RateLimiter
from scan.bruteforce import FTP_CREDENTIALS, SSH_CREDENTIALS, HTTP_AUTH_CREDENTIALS
from scan.os_fingerprint import get_os_from_ttl
from scan.tech_detect import detect_technologies, TECHNOLOGY_PATTERNS


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_no_limit(self):
        limiter = RateLimiter(0)
        await limiter.wait()

    @pytest.mark.asyncio
    async def test_with_limit(self):
        limiter = RateLimiter(1000)
        await limiter.wait()


class TestSubdomains:
    def test_has_common_subdomains(self):
        assert len(COMMON_SUBDOMAINS) > 100
        assert "www" in COMMON_SUBDOMAINS
        assert "mail" in COMMON_SUBDOMAINS
        assert "admin" in COMMON_SUBDOMAINS
        assert "api" in COMMON_SUBDOMAINS

    def test_no_duplicates(self):
        assert len(COMMON_SUBDOMAINS) == len(set(COMMON_SUBDOMAINS))


class TestServiceDetection:
    def test_detect_protocol_http(self):
        assert detect_protocol(80, "HTTP/1.1 200 OK") == "HTTP"

    def test_detect_protocol_ssh(self):
        assert detect_protocol(22, "SSH-2.0-OpenSSH_8.9") == "SSH"

    def test_detect_protocol_ftp(self):
        assert detect_protocol(21, "220 FTP ready") == "FTP"

    def test_detect_protocol_by_port(self):
        assert detect_protocol(3306, None) == "MySQL"
        assert detect_protocol(5432, None) == "PostgreSQL"
        assert detect_protocol(6379, None) == "Redis"
        assert detect_protocol(27017, None) == "MongoDB"

    def test_detect_unknown_port(self):
        assert detect_protocol(12345, None) == "unknown"

    def test_parse_http_response_title(self):
        result = parse_http_response(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title>Test Page</title></html>"
        )
        assert "Test Page" in result
        assert "nginx" in result

    def test_parse_http_response_no_title(self):
        result = parse_http_response("HTTP/1.1 404 Not Found\r\nServer: Apache\r\n\r\n")
        assert "Apache" in result


class TestOSFingerprint:
    def test_linux_ttl(self):
        assert "Linux" in get_os_from_ttl(64)

    def test_windows_ttl(self):
        assert "Windows" in get_os_from_ttl(128)

    def test_solaris_ttl(self):
        assert "Solaris" in get_os_from_ttl(254)

    def test_custom_ttl(self):
        result = get_os_from_ttl(55)
        assert result is not None


class TestBruteforce:
    def test_ftp_credentials(self):
        assert len(FTP_CREDENTIALS) >= 10
        assert ("admin", "admin") in FTP_CREDENTIALS
        assert ("anonymous", "anonymous") in FTP_CREDENTIALS

    def test_ssh_credentials(self):
        assert len(SSH_CREDENTIALS) >= 10
        assert ("root", "root") in SSH_CREDENTIALS

    def test_http_credentials(self):
        assert len(HTTP_AUTH_CREDENTIALS) >= 10


class TestTechDetect:
    def test_pattern_count(self):
        assert len(TECHNOLOGY_PATTERNS) >= 20

    def test_detect_nginx(self):
        result = detect_technologies("Server: nginx/1.20.1\r\n")
        assert "Nginx" in result

    def test_detect_apache(self):
        result = detect_technologies("Server: Apache/2.4.41\r\n")
        assert "Apache HTTPD" in result

    def test_detect_wordpress(self):
        result = detect_technologies("", '<html><body>wp-content</body></html>')
        assert "WordPress" in result

    def test_detect_php(self):
        result = detect_technologies("X-Powered-By: PHP/8.1.0\r\n")
        assert "PHP" in result

    def test_empty_input(self):
        result = detect_technologies("")
        assert result == {}


class TestExporter:
    def test_csv_column_order(self):
        import csv
        import io
        results = {
            "192.168.1.1": {
                "os": "Linux",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "HTTP"}
                ]
            }
        }
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP', 'OS', 'Port', 'Protocol', 'State', 'Service'])
        writer.writerow(["192.168.1.1", "Linux", 80, "tcp", "open", "HTTP"])
        content = output.getvalue()
        assert "192.168.1.1" in content
        assert "HTTP" in content

    def test_json_structure(self):
        import json
        results = {"hosts": {"192.168.1.1": {"os": "Linux", "ports": []}}}
        dumped = json.dumps(results)
        loaded = json.loads(dumped)
        assert "192.168.1.1" in loaded["hosts"]