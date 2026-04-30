import socket
import ipaddress
import threading
from collections import defaultdict
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class NetworkScanner:
    def __init__(self):
        self.results = []
        self.timeout = 3
        self.max_workers = 50  # Increased from 20 for faster scanning
        self.common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT',
        }

    def is_valid_ip(self, ip_string):
        """Check if string is valid IP address"""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    def is_valid_network(self, network_string):
        """Check if string is valid network"""
        try:
            ipaddress.ip_network(network_string, strict=False)
            return True
        except ValueError:
            return False

    def ping_host(self, ip):
        """Check if host is reachable via DNS lookup"""
        # Localhost is always available
        if ip == '127.0.0.1' or ip == 'localhost':
            return True, 'localhost'
        
        try:
            socket.setdefaulttimeout(1)
            result = socket.gethostbyaddr(ip)
            hostname = result[0]
            return True, hostname
        except (socket.timeout, socket.herror, socket.gaierror):
            # Try reverse lookup as fallback
            try:
                socket.setdefaulttimeout(1)
                result = socket.gethostbyname(ip)
                return True, None
            except:
                return False, None

    def scan_port(self, ip, port):
        """Scan a single port with proper error handling"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Reduced timeout to 1 second
            
            try:
                result = sock.connect_ex((str(ip), int(port)))
                if result == 0:
                    try:
                        service = socket.getservbyport(int(port))
                    except:
                        service = self.common_ports.get(int(port), 'UNKNOWN')
                    return True, service
                return False, None
            finally:
                try:
                    sock.close()
                except:
                    pass
        except (socket.timeout, socket.error, OSError, ValueError):
            return False, None
        except Exception as e:
            return False, None

    def scan_ports_threaded(self, target, port_range='1-1000'):
        """Scan ports on target using threading for speed"""
        if not self.is_valid_ip(target):
            return {'error': 'Invalid IP address - please provide a valid IPv4 address'}
        
        try:
            # Validate target is reachable
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            # Try to connect to a common port to check if host exists
            test_result = test_socket.connect_ex((str(target), 80))
            test_socket.close()
            # If connect_ex returns anything other than 0, the host might not be reachable
            # But we continue anyway since some hosts block ICMP
        except:
            pass
        
        # Parse port range
        try:
            if '-' in port_range:
                start, end = map(int, str(port_range).split('-'))
            else:
                start = end = int(port_range)
            
            # Validate port range
            start = max(1, min(int(start), 65535))
            end = max(1, min(int(end), 65535))
            
            if start > end:
                start, end = end, start
        except (ValueError, TypeError):
            return {'error': 'Invalid port range - use format: 1-1000 or single port: 80'}
        
        # Limit the range to prevent excessive scanning
        port_count = end - start + 1
        if port_count > 10000:
            end = start + 9999
            port_count = 10000
        
        open_ports = []
        scanned_count = 0
        
        # Use ThreadPoolExecutor for parallel scanning
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all port scans
                future_to_port = {
                    executor.submit(self.scan_port, target, port): port 
                    for port in range(start, end + 1)
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    scanned_count += 1
                    try:
                        is_open, service = future.result(timeout=5)
                        if is_open:
                            open_ports.append({
                                'port': port,
                                'service': service or 'UNKNOWN',
                                'status': 'OPEN'
                            })
                    except Exception as e:
                        pass  # Port scan failed, skip
        except Exception as e:
            return {'error': f'Scanning error: {str(e)}'}
        
        # Sort by port number
        open_ports.sort(key=lambda x: x['port'])
        
        return {
            'target': str(target),
            'open_ports': open_ports,
            'open_ports_count': len(open_ports),
            'total_scanned': port_count,
            'scan_range': f'{start}-{end}',
            'status': 'completed'
        }

    def scan_ports(self, target, port_range='1-1000'):
        """Scan ports on target (wrapper for threaded version)"""
        return self.scan_ports_threaded(target, port_range)

    def scan(self, target, scan_type='basic'):
        """Scan network or host"""
        if self.is_valid_network(target):
            return self.scan_network(target, scan_type)
        elif self.is_valid_ip(target):
            return self.scan_host(target, scan_type)
        else:
            return {'error': 'Invalid target IP or network'}

    def scan_host(self, ip, scan_type='basic'):
        """Scan single host with open ports"""
        results = {
            'target': ip,
            'status': 'OFFLINE',
            'hostname': None,
            'open_ports': []
        }
        
        # Check if host is alive
        is_alive, hostname = self.ping_host(ip)
        results['status'] = 'ONLINE' if is_alive else 'OFFLINE'
        results['hostname'] = hostname
        
        # Always scan even if ping_host failed (some systems block ICMP)
        # We can infer host is online if we find open ports
        if scan_type in ['basic', 'advanced']:
            # Determine port range based on scan type
            if scan_type == 'basic':
                # Basic scan: check common ports + extended range (1-2000)
                ports_to_scan = set(self.common_ports.keys())
                ports_to_scan.update(range(1, 2001))
            else:
                # Advanced scan: broader range (1-10000)
                ports_to_scan = set(range(1, 10001))
            
            # Scan ports using threading
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, ip, port): port 
                    for port in ports_to_scan
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, service = future.result()
                        if is_open:
                            results['open_ports'].append({
                                'port': port,
                                'service': service or 'UNKNOWN',
                                'status': 'OPEN'
                            })
                            # If we find an open port, the host is definitely online
                            if results['status'] == 'OFFLINE':
                                results['status'] = 'ONLINE'
                    except Exception as e:
                        pass
            
            # Sort ports
            results['open_ports'].sort(key=lambda x: x['port'])
        
        return results

    def scan_network(self, network_range, scan_type='basic'):
        """Scan network range and find open ports on active hosts"""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            return {'error': 'Invalid network'}
        
        active_hosts = []
        results = {
            'network': str(network),
            'active_hosts': [],
            'total_hosts': network.num_addresses,
            'scanned_hosts': 0
        }
        
        # Get all hosts in network (for /32, include the single IP)
        if network.num_addresses == 1:
            # Single IP case (e.g., 127.0.0.1/32) - scan ports on this host
            hosts = [network.network_address]
        else:
            hosts = list(network.hosts())[:50]  # Limit to 50 hosts
        
        for ip in hosts:
            ip_str = str(ip)
            is_alive, hostname = self.ping_host(ip_str)
            
            # Determine port range based on scan type
            if scan_type == 'basic':
                ports_to_scan = set(self.common_ports.keys())
                ports_to_scan.update(range(1, 2001))
            else:
                ports_to_scan = set(range(1, 5001))  # Limit advanced to 5000 for network scan
            
            open_ports = []
            
            # Scan ports on this host
            with ThreadPoolExecutor(max_workers=30) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, ip_str, port): port 
                    for port in ports_to_scan
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, service = future.result()
                        if is_open:
                            open_ports.append({
                                'port': port,
                                'service': service or 'UNKNOWN',
                                'status': 'OPEN'
                            })
                            # If we find an open port, host is definitely alive
                            is_alive = True
                    except Exception as e:
                        pass
            
            # Sort ports
            open_ports.sort(key=lambda x: x['port'])
            
            host_info = {
                'target': ip_str,
                'ip': ip_str,
                'hostname': hostname,
                'status': 'ONLINE' if is_alive else 'OFFLINE',
                'alive': is_alive,
                'open_ports': open_ports
            }
            
            active_hosts.append(host_info)
            results['scanned_hosts'] += 1
        
        results['active_hosts'] = active_hosts
        results['active_hosts_count'] = len([h for h in active_hosts if h['status'] == 'ONLINE'])
        results['open_ports_found'] = sum(len(h['open_ports']) for h in active_hosts)
        
        return results

    def get_interfaces(self):
        """Get network interfaces"""
        try:
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': [local_ip]
            }
        except:
            return {
                'hostname': 'Unknown',
                'local_ip': '127.0.0.1',
                'interfaces': ['127.0.0.1']
            }
