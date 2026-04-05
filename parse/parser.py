import ipaddress
import socket

def parse_targets(target_string):
    """
    Parse a target string into a list of IP addresses.
    Supports single IP, CIDR notation, and IP ranges (e.g., 192.168.1.1-50).
    Also resolves hostnames to IP addresses.
    """
    ips = []
    
    # Check for comma-separated targets
    parts = target_string.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        try:
            # Check for CIDR (e.g., 192.168.1.0/24)
            if '/' in part:
                network = ipaddress.ip_network(part, strict=False)
                ips.extend([str(ip) for ip in network.hosts()])
                
            # Check for hyphen range (e.g., 192.168.1.1-100)
            elif '-' in part:
                start_ip_str, end_suffix = part.split('-', 1)
                start_ip = ipaddress.ip_address(start_ip_str)
                
                # If end_suffix is a full IP
                if '.' in end_suffix:
                    end_ip = ipaddress.ip_address(end_suffix)
                else:
                    # If end_suffix is just the last octet (e.g. 192.168.1.1-50)
                    ip_parts = start_ip_str.split('.')
                    ip_parts[-1] = end_suffix
                    end_ip = ipaddress.ip_address('.'.join(ip_parts))
                
                start_int = int(start_ip)
                end_int = int(end_ip)
                
                if start_int > end_int:
                    start_int, end_int = end_int, start_int
                    
                for i in range(start_int, end_int + 1):
                    ips.append(str(ipaddress.ip_address(i)))
                    
            else:
                # Single IP or Hostname
                try:
                    ip = ipaddress.ip_address(part)
                    ips.append(str(ip))
                except ValueError:
                    # Attempt hostname resolution
                    resolved_ip = socket.gethostbyname(part)
                    ips.append(resolved_ip)
                    
        except Exception as e:
            print(f"Error parsing target '{part}': {e}")
            
    return sorted(list(set(ips)), key=lambda ip: int(ipaddress.ip_address(ip)))

def parse_ports(port_string):
    """
    Parse a port string into a list of integers.
    Supports single ports, comma-separated, and ranges (e.g., 80,443,1000-2000).
    Also supports 'all' and 'top1000'.
    """
    if port_string.lower() == 'all':
        return list(range(1, 65536))
    elif port_string.lower() == 'top100':
        # Just a basic subset for 'top'
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
    ports = []
    parts = port_string.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        try:
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                if start > end:
                    start, end = end, start
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        except ValueError:
            print(f"Error parsing port '{part}': Invalid format")
            
    # Filter valid ports and remove duplicates
    valid_ports = sorted(list(set([p for p in ports if 1 <= p <= 65535])))
    return valid_ports
