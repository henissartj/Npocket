import os

class Config:
    """
    Global configuration object to hold scanning settings.
    """
    def __init__(self):
        self.targets = []
        self.ports = []
        self.timeout = 1.5
        self.concurrency = 500  # Default to 500 to avoid socket exhaustion on Windows
        self.verbose = False
        self.output_format = 'txt'
        self.output_file = None
        self.scan_type = 'tcp'
        self.service_detection = False
        self.os_fingerprint = False
        self.show_progress = True
        
        # Advanced Features
        self.adaptive_timing = False
        self.timeout_strikes = 0
        
    def __str__(self):
        return (f"Targets: {len(self.targets)}, Ports: {len(self.ports)}, "
                f"Concurrency: {self.concurrency}, Timeout: {self.timeout}s")

# Global config instance
config = Config()
