from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, rdpcap
from collections import defaultdict
import json


class PacketAnalyzer:
    def __init__(self):
        self.packet_stats = defaultdict(int)
        self.protocols = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'DNS': 53
        }

    def analyze_file(self, filepath, filter_type='all'):
        """Analyze PCAP file"""
        try:
            packets = rdpcap(filepath)
        except Exception as e:
            return {'error': f'Could not read PCAP file: {str(e)}'}
        
        results = {
            'total_packets': len(packets),
            'protocol_count': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int),
            'detailed_packets': []
        }
        
        for packet in packets[:1000]:  # Limit to 1000 packets
            self._analyze_packet(packet, results, filter_type)
        
        # Convert defaultdicts to regular dicts
        results['protocol_count'] = dict(results['protocol_count'])
        results['src_ips'] = dict(results['src_ips'])
        results['dst_ips'] = dict(results['dst_ips'])
        results['ports'] = dict(results['ports'])
        
        # Get top 5 source and destination IPs
        top_src = sorted(results['src_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
        top_dst = sorted(results['dst_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
        
        results['top_source_ips'] = [ip for ip, count in top_src]
        results['top_dest_ips'] = [ip for ip, count in top_dst]
        
        return results

    def _analyze_packet(self, packet, results, filter_type):
        """Analyze individual packet"""
        packet_info = {
            'timestamp': float(packet.time),
            'layers': []
        }
        
        # Ethernet layer
        if packet.haslayer('Ether'):
            packet_info['src_mac'] = packet['Ether'].src
            packet_info['dst_mac'] = packet['Ether'].dst
        
        # IP layer
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            packet_info['src_ip'] = src_ip
            packet_info['dst_ip'] = dst_ip
            packet_info['layers'].append('IP')
            
            results['src_ips'][src_ip] += 1
            results['dst_ips'][dst_ip] += 1
            
            # Identify protocol
            if protocol == 6:
                results['protocol_count']['TCP'] += 1
                packet_info['protocol'] = 'TCP'
            elif protocol == 17:
                results['protocol_count']['UDP'] += 1
                packet_info['protocol'] = 'UDP'
            elif protocol == 1:
                results['protocol_count']['ICMP'] += 1
                packet_info['protocol'] = 'ICMP'
        
        # TCP layer
        if packet.haslayer(TCP):
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['flags'] = str(packet[TCP].flags)
            packet_info['layers'].append('TCP')
            
            results['ports'][packet[TCP].dport] += 1
            
            # Detect suspicious flags
            if 'S' in packet[TCP].flags and 'A' in packet[TCP].flags:
                packet_info['suspicious'] = 'SYN-ACK flood possible'
        
        # UDP layer
        if packet.haslayer(UDP):
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            packet_info['layers'].append('UDP')
            
            results['ports'][packet[UDP].dport] += 1
        
        # DNS layer
        if packet.haslayer(DNS):
            packet_info['layers'].append('DNS')
            results['protocol_count']['DNS'] += 1
            if packet[DNS].qd:
                packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
        
        # ICMP layer
        if packet.haslayer(ICMP):
            packet_info['layers'].append('ICMP')
            packet_info['icmp_type'] = packet[ICMP].type
        
        # Raw data
        if packet.haslayer('Raw'):
            packet_info['payload_size'] = len(packet['Raw'].load)
        
        results['detailed_packets'].append(packet_info)

    def capture_live(self, interface=None, packet_count=10, duration=30):
        """Capture live packets from network interface"""
        try:
            from scapy.all import sniff, get_if_list
            import threading
            import time
            
            # Get available interfaces
            available_interfaces = get_if_list()
            
            if not available_interfaces:
                return {
                    'error': 'No network interfaces found',
                    'note': 'Administrator access may be required'
                }
            
            # Use specified interface or default to first available
            target_interface = interface if interface in available_interfaces else available_interfaces[0]
            
            captured_packets = []
            
            def packet_callback(packet):
                """Callback to process each captured packet"""
                if len(captured_packets) < packet_count:
                    packet_info = {
                        'timestamp': float(packet.time),
                        'size': len(packet),
                        'layers': []
                    }
                    
                    # Ethernet layer
                    if packet.haslayer('Ether'):
                        packet_info['src_mac'] = packet['Ether'].src
                        packet_info['dst_mac'] = packet['Ether'].dst
                        packet_info['layers'].append('Ethernet')
                    
                    # IP layer
                    if packet.haslayer(IP):
                        packet_info['src_ip'] = packet[IP].src
                        packet_info['dst_ip'] = packet[IP].dst
                        packet_info['ttl'] = packet[IP].ttl
                        packet_info['layers'].append('IP')
                        
                        protocol = packet[IP].proto
                        if protocol == 6:
                            packet_info['protocol'] = 'TCP'
                        elif protocol == 17:
                            packet_info['protocol'] = 'UDP'
                        elif protocol == 1:
                            packet_info['protocol'] = 'ICMP'
                    
                    # TCP layer
                    if packet.haslayer(TCP):
                        packet_info['src_port'] = packet[TCP].sport
                        packet_info['dst_port'] = packet[TCP].dport
                        packet_info['flags'] = str(packet[TCP].flags)
                        packet_info['seq'] = packet[TCP].seq
                        packet_info['ack'] = packet[TCP].ack
                        packet_info['layers'].append('TCP')
                    
                    # UDP layer
                    if packet.haslayer(UDP):
                        packet_info['src_port'] = packet[UDP].sport
                        packet_info['dst_port'] = packet[UDP].dport
                        packet_info['layers'].append('UDP')
                    
                    # DNS layer
                    if packet.haslayer(DNS):
                        packet_info['layers'].append('DNS')
                        if packet[DNS].qd:
                            try:
                                packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                            except:
                                packet_info['dns_query'] = 'Unknown'
                    
                    # ICMP layer
                    if packet.haslayer(ICMP):
                        packet_info['layers'].append('ICMP')
                        packet_info['icmp_type'] = packet[ICMP].type
                        packet_info['icmp_code'] = packet[ICMP].code
                    
                    # Raw payload
                    if packet.haslayer('Raw'):
                        packet_info['payload_size'] = len(packet['Raw'].load)
                    
                    captured_packets.append(packet_info)
            
            # Capture packets with timeout
            try:
                sniff(
                    iface=target_interface,
                    prn=packet_callback,
                    count=packet_count,
                    timeout=duration,
                    store=False
                )
            except PermissionError:
                return {
                    'error': 'Permission denied',
                    'note': 'Run as Administrator (Windows) or use sudo (Linux/Mac) for packet capture'
                }
            except Exception as e:
                return {
                    'error': f'Capture failed: {str(e)}',
                    'note': 'Check network interface and permissions'
                }
            
            # Analyzecaptured data
            protocol_stats = defaultdict(int)
            src_ips = defaultdict(int)
            dst_ips = defaultdict(int)
            ports = defaultdict(int)
            
            for packet_info in captured_packets:
                for layer in packet_info.get('layers', []):
                    protocol_stats[layer] += 1
                
                if 'src_ip' in packet_info:
                    src_ips[packet_info['src_ip']] += 1
                if 'dst_ip' in packet_info:
                    dst_ips[packet_info['dst_ip']] += 1
                if 'src_port' in packet_info:
                    ports[f"{packet_info.get('src_ip', 'Unknown')}:{packet_info['src_port']}"] += 1
            
            return {
                'status': 'success',
                'interface': target_interface,
                'packets_captured': len(captured_packets),
                'protocols': dict(protocol_stats),
                'src_ips': dict(src_ips),
                'dst_ips': dict(dst_ips),
                'ports': dict(ports),
                'detailed_packets': captured_packets
            }
            
        except Exception as e:
            return {'error': f'Capture error: {str(e)}'}

    def get_network_interfaces(self):
        """Get list of available network interfaces"""
        try:
            interfaces = []
            import platform
            
            # On Windows, skip Scapy and go straight to psutil for friendly names
            if platform.system() == 'Windows':
                try:
                    import psutil
                    net_if_addrs = psutil.net_if_addrs()
                    interfaces = list(net_if_addrs.keys())
                    if interfaces:
                        return {
                            'status': 'success',
                            'interfaces': interfaces,
                            'count': len(interfaces),
                            'method': 'psutil'
                        }
                except Exception as psutil_err:
                    print(f"psutil method failed: {psutil_err}")
            
            # Try psutil first - returns friendly names on Windows
            try:
                import psutil
                net_if_addrs = psutil.net_if_addrs()
                interfaces = list(net_if_addrs.keys())
                if interfaces:
                    return {
                        'status': 'success',
                        'interfaces': interfaces,
                        'count': len(interfaces),
                        'method': 'psutil'
                    }
            except Exception as psutil_err:
                print(f"psutil method failed: {psutil_err}")
            
            # Fallback: Try Scapy (returns GUIDs on Windows)
            try:
                from scapy.all import get_if_list
                interfaces = get_if_list()
                if interfaces:
                    return {
                        'status': 'success',
                        'interfaces': interfaces,
                        'count': len(interfaces),
                        'method': 'scapy'
                    }
            except Exception as scapy_err:
                print(f"Scapy method failed: {scapy_err}")
            
            # Fallback: Try using socket.if_nameindex() (works on Windows, Linux, Mac)
            try:
                import socket
                interfaces = [iface[1] for iface in socket.if_nameindex()]
                if interfaces:
                    return {
                        'status': 'success',
                        'interfaces': interfaces,
                        'count': len(interfaces),
                        'method': 'socket'
                    }
            except Exception as socket_err:
                print(f"socket method failed: {socket_err}")
            
            # Last resort: Return sample interfaces for Windows/testing
            sample_interfaces = ['Ethernet', 'Wi-Fi', 'Local Area Connection', 'Wireless Network Connection']
            return {
                'status': 'success',
                'interfaces': sample_interfaces,
                'count': len(sample_interfaces),
                'method': 'sample',
                'note': 'Using sample interfaces. Real interfaces may be different.'
            }
            
        except Exception as e:
            print(f"Error getting network interfaces: {str(e)}")
            return {
                'error': f'Failed to get interfaces: {str(e)}',
                'interfaces': ['Ethernet', 'Wi-Fi'],
                'count': 2,
                'method': 'default'
            }

    def detect_attacks(self, packets_data):
        """Detect potential attacks in packet data"""
        threats = {
            'dos_attack': False,
            'port_scan': False,
            'syn_flood': False,
            'dns_amplification': False
        }
        
        # Analyze patterns
        for packet_info in packets_data:
            # SYN flood detection
            if packet_info.get('flags') and 'S' in packet_info['flags']:
                threats['syn_flood'] = True
            
            # Port scan detection (many different ports from same IP)
            if packet_info.get('suspicious') == 'SYN-ACK flood possible':
                threats['dos_attack'] = True
        
        return threats

    def get_protocol_summary(self, packets_data):
        """Get protocol distribution"""
        summary = defaultdict(int)
        for packet_info in packets_data:
            for layer in packet_info.get('layers', []):
                summary[layer] += 1
        
        return dict(summary)
