from utils.ui import Colors, format_status

def print_banner():
    """
    Print a stylish banner for Npocket.
    """
    banner = f"""{Colors.OKCYAN}{Colors.BOLD}
    _   __                 __        __ 
   / | / /___  ____  _____/ /_____  / /_
  /  |/ / __ \\/ __ \\/ ___/ //_/ _ \\/ __/
 / /|  / /_/ / /_/ / /__/ ,< /  __/ /_  
/_/ |_/ .___/\\____/\\___/_/|_|\\___/\\__/  
     /_/                                
    {Colors.ENDC}"""
    print(banner)
    print(f"{Colors.OKGREEN}The Modern Network Scanner.{Colors.ENDC}\n")

def print_results(results):
    """
    Print the final scan results to the console in a clear format.
    """
    print(f"\n{Colors.OKBLUE}" + "="*50 + f"{Colors.ENDC}")
    print(f"{Colors.BOLD}Npocket Scan Report{Colors.ENDC}")
    print(f"{Colors.OKBLUE}" + "="*50 + f"{Colors.ENDC}")
    
    for ip, data in results.items():
        print(f"\n{Colors.BOLD}Host: {Colors.OKCYAN}{ip}{Colors.ENDC}")
        os_guess = data.get('os', 'Unknown')
        
        # Colorize OS
        if os_guess != 'Unknown':
            print(f"OS Guess: {Colors.OKGREEN}{os_guess}{Colors.ENDC}")
        else:
            print(f"OS Guess: {Colors.WARNING}{os_guess}{Colors.ENDC}")
        
        ports = data.get('ports', [])
        if ports:
            print(f"\n{Colors.BOLD}{'PORT':<10} {'STATE':<15} {'SERVICE':<20} {'EXTRA INFO'}{Colors.ENDC}")
            print("-" * 60)
            for p in ports:
                port_proto = f"{p['port']}/{p['protocol']}"
                colored_state = format_status(p['state'])
                service = p['service'] if p['service'] else 'unknown'
                
                # Truncate service name if it's too long but let it be a bit longer
                service = (service[:37] + '...') if len(service) > 40 else service
                
                # ANSI colors mess up string length formatting, so we calculate padding
                # Since colored_state contains ANSI codes, we pad manually or use f-strings carefully
                state_len = len(p['state'])
                padding = 15 - state_len
                pad_str = " " * padding
                
                base_line = f"{port_proto:<10} {colored_state}{pad_str} {service:<20}"
                
                brute = p.get('bruteforce')
                if brute:
                    if "SUCCESS" in brute:
                        base_line += f" {Colors.FAIL}{Colors.BOLD}[VULNERABLE] {brute}{Colors.ENDC}"
                    else:
                        base_line += f" {Colors.WARNING}[Bruteforce: {brute}]{Colors.ENDC}"
                
                print(base_line)
        else:
            print(f"{Colors.WARNING}No open ports found or scanned.{Colors.ENDC}")
            
    print(f"\n{Colors.OKBLUE}" + "="*50 + f"{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Scan completed successfully.{Colors.ENDC}")
