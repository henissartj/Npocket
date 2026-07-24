import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from utils.config import Config, config
from utils.ui import Colors, format_status, get_terminal_width
from utils.logger import setup_logger


class TestConfig:
    def test_default_values(self):
        c = Config()
        assert c.timeout == 1.5
        assert c.concurrency == 500
        assert c.scan_type == 'tcp'
        assert c.verbose is False
        assert c.service_detection is False

    def test_string_representation(self):
        c = Config()
        assert "Timeout: 1.5" in str(c)
        assert "Ports: 0" in str(c)

    def test_reset(self):
        c = Config()
        c.timeout = 5.0
        c.reset()
        assert c.timeout == 1.5


class TestColors:
    def test_green(self):
        result = Colors.green("test")
        assert "\033[92m" in result
        assert "test" in result
        assert "\033[0m" in result

    def test_red(self):
        result = Colors.red("test")
        assert "\033[91m" in result

    def test_yellow(self):
        result = Colors.yellow("test")
        assert "\033[93m" in result

    def test_colorize_bold(self):
        result = Colors.colorize("test", Colors.OKGREEN, bold=True)
        assert "\033[1m" in result
        assert "\033[92m" in result


class TestUi:
    def test_format_status_open(self):
        result = format_status("open")
        assert "\033[92m" in result

    def test_format_status_filtered(self):
        result = format_status("filtered")
        assert "\033[93m" in result

    def test_format_status_closed(self):
        result = format_status("closed")
        assert "\033[91m" in result

    def test_terminal_width(self):
        width = get_terminal_width()
        assert width >= 20


class TestLogger:
    def test_logger_creation(self):
        test_logger = setup_logger("test-npocket")
        assert test_logger.name == "test-npocket"
        assert len(test_logger.handlers) > 0

    def test_logger_level(self):
        import logging
        test_logger = setup_logger("test-level", level=logging.DEBUG)
        assert test_logger.level == logging.DEBUG