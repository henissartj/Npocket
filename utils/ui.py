import sys
import shutil

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

def get_terminal_width():
    return shutil.get_terminal_size((80, 20)).columns

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    """
    if total == 0:
        return
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    
    # Use cyan color for the bar
    sys.stdout.write(f'\r{Colors.OKCYAN}{prefix} |{bar}| {percent}% {suffix}{Colors.ENDC}')
    sys.stdout.flush()
    
    # Print New Line on Complete
    if iteration == total: 
        sys.stdout.write('\n')
        sys.stdout.flush()

def format_status(status):
    if 'open' in status:
        return f"{Colors.OKGREEN}{status}{Colors.ENDC}"
    elif 'filtered' in status:
        return f"{Colors.WARNING}{status}{Colors.ENDC}"
    else:
        return f"{Colors.FAIL}{status}{Colors.ENDC}"
