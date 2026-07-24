import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from parse.parser import parse_targets, parse_ports, is_valid_domain, is_valid_ip, extract_domains


class TestTargetParsing:
    def test_single_ip(self):
        assert parse_targets("192.168.1.1") == ["192.168.1.1"]

    def test_cidr_notation(self):
        ips = parse_targets("192.168.1.0/30")
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_hyphen_range(self):
        ips = parse_targets("192.168.1.1-3")
        assert ips == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    def test_comma_separated(self):
        ips = parse_targets("10.0.0.1,10.0.0.2")
        assert ips == ["10.0.0.1", "10.0.0.2"]

    def test_full_ip_range(self):
        ips = parse_targets("192.168.1.1-192.168.1.3")
        assert ips == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    def test_mixed_input(self):
        ips = parse_targets("10.0.0.1,192.168.1.0/31")
        assert "10.0.0.1" in ips
        assert "192.168.1.1" in ips

    def test_empty_string(self):
        assert parse_targets("") == []

    def test_invalid_target(self):
        result = parse_targets("999.999.999.999")
        assert result == []


class TestPortParsing:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_ports(self):
        assert parse_ports("80,443,22") == [22, 80, 443]

    def test_port_range(self):
        assert parse_ports("80-85") == [80, 81, 82, 83, 84, 85]

    def test_reversed_range(self):
        assert parse_ports("85-80") == [80, 81, 82, 83, 84, 85]

    def test_mixed(self):
        ports = parse_ports("80,443,8000-8002")
        assert ports == [80, 443, 8000, 8001, 8002]

    def test_all_ports(self):
        ports = parse_ports("all")
        assert len(ports) == 65535
        assert ports[0] == 1
        assert ports[-1] == 65535

    def test_top100(self):
        ports = parse_ports("top100")
        assert 80 in ports
        assert 443 in ports
        assert len(ports) > 10

    def test_out_of_range(self):
        assert parse_ports("0") == []
        assert parse_ports("65536") == []


class TestValidation:
    def test_valid_domain(self):
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.co.uk")
        assert is_valid_domain("my-server-1.example.com")

    def test_invalid_domain(self):
        assert not is_valid_domain("")
        assert not is_valid_domain("not-a-domain")
        assert not is_valid_domain("192.168.1.1")

    def test_valid_ip(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("0.0.0.0")
        assert is_valid_ip("255.255.255.255")

    def test_invalid_ip(self):
        assert not is_valid_ip("256.1.1.1")
        assert not is_valid_ip("1.1.1")
        assert not is_valid_ip("not-an-ip")

    def test_extract_domains(self):
        assert extract_domains(["example.com", "192.168.1.1"]) == ["example.com"]
        assert extract_domains(["192.168.1.1"]) == []