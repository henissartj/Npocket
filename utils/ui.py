import sys
import shutil
import itertools
import threading
import time
from typing import Optional


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[97m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'

    @staticmethod
    def colorize(text: str, color: str, bold: bool = False) -> str:
        prefix = Colors.BOLD if bold else ''
        return f"{prefix}{color}{text}{Colors.ENDC}"

    @staticmethod
    def green(text: str, bold: bool = False) -> str:
        return Colors.colorize(text, Colors.OKGREEN, bold)

    @staticmethod
    def red(text: str, bold: bool = False) -> str:
        return Colors.colorize(text, Colors.FAIL, bold)

    @staticmethod
    def yellow(text: str, bold: bool = False) -> str:
        return Colors.colorize(text, Colors.WARNING, bold)

    @staticmethod
    def blue(text: str, bold: bool = False) -> str:
        return Colors.colorize(text, Colors.OKBLUE, bold)

    @staticmethod
    def cyan(text: str, bold: bool = False) -> str:
        return Colors.colorize(text, Colors.OKCYAN, bold)

    @staticmethod
    def dim(text: str) -> str:
        return f"{Colors.DIM}{text}{Colors.ENDC}"


def get_terminal_width() -> int:
    return shutil.get_terminal_size((80, 20)).columns


def print_progress_bar(
    iteration: int,
    total: int,
    prefix: str = '',
    suffix: str = '',
    length: int = 50,
    fill: str = '#',
    print_end: str = "\r"
) -> None:
    if total == 0:
        return
    percent = 100 * (iteration / float(total))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{Colors.OKCYAN}{prefix} |{bar}| {percent:.1f}% {suffix}{Colors.ENDC}')
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')
        sys.stdout.flush()


class Spinner:
    def __init__(self, message: str = "", delay: float = 0.1) -> None:
        self._spinner = itertools.cycle(['|', '/', '-', '\\'])
        self._delay = delay
        self._message = message
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self) -> None:
        while self._running:
            sys.stdout.write(f"\r{Colors.OKCYAN}{next(self._spinner)} {self._message}{Colors.ENDC}")
            sys.stdout.flush()
            time.sleep(self._delay)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join()
        sys.stdout.write("\r" + " " * (len(self._message) + 4) + "\r")
        sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def format_status(status: str) -> str:
    if 'open' in status:
        return f"{Colors.OKGREEN}{status}{Colors.ENDC}"
    elif 'filtered' in status:
        return f"{Colors.WARNING}{status}{Colors.ENDC}"
    else:
        return f"{Colors.FAIL}{status}{Colors.ENDC}"


def table_row(fields: list, widths: list, colors: Optional[list] = None) -> str:
    parts = []
    for i, field in enumerate(fields):
        w = widths[i] if i < len(widths) else 10
        val = str(field)
        if len(val) > w:
            val = val[:w - 3] + '...'
        if colors and i < len(colors) and colors[i]:
            val = f"{colors[i]}{val}{Colors.ENDC}"
        parts.append(val.ljust(w))
    return '  '.join(parts)


def separator(char: str = '=', length: Optional[int] = None) -> str:
    if length is None:
        length = get_terminal_width()
    return char * length


def print_header(text: str) -> None:
    width = get_terminal_width()
    print(f"\n{Colors.OKBLUE}{Colors.BOLD}{'=' * width}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.OKCYAN}{text.center(width)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{Colors.BOLD}{'=' * width}{Colors.ENDC}")