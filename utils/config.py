import os
from typing import List, Optional, Dict, Any


class Config:
    def __init__(self) -> None:
        # Target & Port configuration
        self.targets: List[str] = []
        self.ports: List[int] = []
        self.scan_type: str = 'tcp'

        # Performance
        self.timeout: float = 1.5
        self.concurrency: int = 500
        self.rate_limit: float = 0.0

        # Scan phases
        self.ping_scan_only: bool = False
        self.service_detection: bool = False
        self.os_fingerprint: bool = False
        self.subdomain_enum: bool = False
        self.bruteforce: bool = False
        self.dns_enum: bool = False
        self.traceroute: bool = False
        self.vuln_check: bool = False
        self.tech_detect: bool = False
        self.interactive: bool = False

        # Advanced
        self.adaptive_timing: bool = False
        self.timeout_strikes: int = 0
        self.aggressive: bool = False

        # Output
        self.verbose: bool = False
        self.show_progress: bool = True
        self.output_format: str = 'txt'
        self.output_file: Optional[str] = None
        self.log_file: Optional[str] = None

        # Bruteforce
        self.bruteforce_wordlist: Optional[str] = None
        self.bruteforce_threads: int = 10

        # Host discovery
        self.skip_discovery: bool = False
        self.tcp_ping: bool = False
        self.tcp_ping_port: int = 80

        # DNS
        self.dns_server: Optional[str] = None

        # Vulnerability
        self.vuln_db_path: Optional[str] = None

    def __str__(self) -> str:
        return (
            f"Targets: {len(self.targets)}, Ports: {len(self.ports)}, "
            f"Concurrency: {self.concurrency}, Timeout: {self.timeout}s, "
            f"Type: {self.scan_type}"
        )

    def reset(self) -> None:
        self.__init__()


config: Config = Config()