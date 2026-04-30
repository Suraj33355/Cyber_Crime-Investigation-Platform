import re
import ipaddress
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class ThreatIntelligence:
    def __init__(self):
        # Known malicious indicators
        self.malicious_ips = {
            '192.168.1.1': {'threat_level': 'medium', 'type': 'port_scanner'},
            '10.0.0.1': {'threat_level': 'high', 'type': 'botnet_command'},
        }
        
        # Safe/Trusted IPs
        self.safe_ips = {
            '127.0.0.1': {'threat_level': 'none', 'type': 'localhost'},
            '::1': {'threat_level': 'none', 'type': 'localhost_ipv6'},
            '8.8.8.8': {'threat_level': 'low', 'type': 'public_dns'},
            '1.1.1.1': {'threat_level': 'low', 'type': 'public_dns'},
            '9.9.9.9': {'threat_level': 'low', 'type': 'public_dns'},
        }
        
        self.malicious_domains = {
            'malware-c2.com': {'threat_level': 'critical', 'type': 'botnet_c2'},
            'phishing-site.net': {'threat_level': 'high', 'type': 'phishing'},
        }
        
        self.threat_signatures = {
            'sql_injection': {
                'patterns': [r"union.*select", r"insert.*into", r"drop.*table"],
                'severity': 'critical',
                'category': 'injection_attack'
            },
            'xss_attack': {
                'patterns': [r"<script", r"javascript:", r"onerror", r"onload"],
                'severity': 'high',
                'category': 'injection_attack'
            },
            'dos_attack': {
                'patterns': [r"syn.*flood", r"udp.*flood", r"ping.*flood"],
                'severity': 'critical',
                'category': 'denial_service'
            },
            'brute_force': {
                'patterns': [r"failed.*login", r"unauthorized.*access", r"invalid.*password"],
                'severity': 'high',
                'category': 'unauthorized_access'
            },
            'malware': {
                'patterns': [r"executable.*detected", r"trojan", r"ransomware"],
                'severity': 'critical',
                'category': 'malware'
            },
            'privilege_escalation': {
                'patterns': [r"sudo", r"admin", r"root.*access"],
                'severity': 'high',
                'category': 'privilege_escalation'
            }
        }

    def detect_threats(self, logs, network_data):
        """Detect threats from logs and network data"""
        threats = []
        
        # Analyze logs
        if logs:
            for log_entry in logs:
                detected = self._analyze_log_entry(log_entry)
                threats.extend(detected)
        
        # Analyze network data
        if network_data:
            detected = self._analyze_network_data(network_data)
            threats.extend(detected)
        
        # Remove duplicates and sort by severity
        threat_severity = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        unique_threats = {}
        
        for threat in threats:
            key = f"{threat['type']}_{threat['indicator']}"
            if key not in unique_threats:
                unique_threats[key] = threat
        
        sorted_threats = sorted(
            unique_threats.values(),
            key=lambda x: threat_severity.get(x['severity'], 4)
        )
        
        return sorted_threats

    def _analyze_log_entry(self, log_entry):
        """Analyze individual log entry"""
        detected_threats = []
        
        log_text = str(log_entry).lower()
        
        for threat_name, threat_info in self.threat_signatures.items():
            for pattern in threat_info['patterns']:
                if re.search(pattern, log_text, re.IGNORECASE):
                    detected_threats.append({
                        'type': threat_name,
                        'severity': threat_info['severity'],
                        'category': threat_info['category'],
                        'indicator': log_entry[:50],
                        'timestamp': None
                    })
                    break  # Only count once per threat type per log
        
        return detected_threats

    def _analyze_network_data(self, network_data):
        """Analyze network data for threats"""
        detected_threats = []
        
        # Check source IPs
        if 'open_ports' in network_data:
            for port_info in network_data['open_ports']:
                port = port_info.get('port')
                # Detect suspicious ports
                if port in [4444, 5555, 6666, 7777, 8123, 8888, 9999]:
                    detected_threats.append({
                        'type': 'suspicious_port',
                        'severity': 'medium',
                        'category': 'network_anomaly',
                        'indicator': f"Port {port} open",
                        'timestamp': None
                    })
        
        return detected_threats

    def check_ip_reputation(self, ip):
        """Check reputation of an IP address"""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {'error': 'Invalid IP address'}
        
        # Check if in safe/trusted list first
        if ip in self.safe_ips:
            return {
                'ip': ip,
                'status': 'clean',
                'reputation': 'safe',
                'threat_level': 'low',
                'threat_type': self.safe_ips[ip]['type'],
                'details': 'IP is in trusted/safe list',
                'indicators': []
            }
        
        # Check if in malicious list
        if ip in self.malicious_ips:
            return {
                'ip': ip,
                'status': 'malicious',
                'reputation': 'malicious',
                'threat_level': self.malicious_ips[ip]['threat_level'],
                'threat_type': self.malicious_ips[ip]['type'],
                'details': 'IP detected as malicious',
                'indicators': ['Listed in threat database']
            }
        
        # Generate reputation based on IP patterns
        # Private IPs are typically safe
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    'ip': ip,
                    'status': 'clean',
                    'reputation': 'safe',
                    'threat_level': 'low',
                    'threat_type': 'private_ip',
                    'details': 'Private IP address range',
                    'indicators': []
                }
        except:
            pass
        
        # Default to unknown (public IPs with no data)
        return {
            'ip': ip,
            'status': 'unknown',
            'reputation': 'unknown',
            'threat_level': 'low',
            'threat_type': 'unverified',
            'details': 'No threat information available',
            'indicators': ['No threats detected']
        }

    def check_domain_reputation(self, domain):
        """Check reputation of a domain"""
        domain_lower = domain.lower()
        
        if domain_lower in self.malicious_domains:
            return {
                'domain': domain,
                'reputation': 'malicious',
                'threat_level': self.malicious_domains[domain_lower]['threat_level'],
                'threat_type': self.malicious_domains[domain_lower]['type'],
                'indicators': ['Listed in threat database']
            }
        
        return {
            'domain': domain,
            'reputation': 'unknown',
            'threat_level': 'low',
            'threat_type': 'unverified',
            'indicators': ['No threats detected']
        }

    def get_threat_analysis(self, threat_type):
        """Get detailed analysis of a threat type"""
        if threat_type not in self.threat_signatures:
            return {'error': 'Unknown threat type'}
        
        threat = self.threat_signatures[threat_type]
        
        return {
            'threat_type': threat_type,
            'severity': threat['severity'],
            'category': threat['category'],
            'patterns': threat['patterns'],
            'description': self._get_threat_description(threat_type),
            'mitigation': self._get_mitigation_steps(threat_type)
        }

    def _get_threat_description(self, threat_type):
        """Get description of threat"""
        descriptions = {
            'sql_injection': 'SQL Injection attacks attempt to manipulate database queries by injecting malicious SQL code.',
            'xss_attack': 'Cross-Site Scripting (XSS) attacks inject malicious scripts into web applications.',
            'dos_attack': 'Denial of Service (DoS) attacks overwhelm systems with traffic to make them unavailable.',
            'brute_force': 'Brute Force attacks attempt to gain unauthorized access by trying multiple credentials.',
            'malware': 'Malware detection indicates presence of malicious software.',
            'privilege_escalation': 'Privilege Escalation attempts to gain higher-level access to systems.'
        }
        return descriptions.get(threat_type, 'Unknown threat type')

    def _get_mitigation_steps(self, threat_type):
        """Get mitigation steps for threat"""
        mitigations = {
            'sql_injection': [
                'Use parameterized queries',
                'Implement input validation',
                'Apply WAF rules',
                'Use ORM frameworks'
            ],
            'xss_attack': [
                'Sanitize user input',
                'Use Content Security Policy (CSP)',
                'Encode output',
                'Use security headers'
            ],
            'dos_attack': [
                'Implement rate limiting',
                'Use DDoS protection services',
                'Configure firewalls',
                'Set up traffic filtering'
            ],
            'brute_force': [
                'Implement account lockout',
                'Use strong password policies',
                'Enable MFA',
                'Monitor authentication logs'
            ],
            'malware': [
                'Update antivirus software',
                'Isolate infected systems',
                'Conduct full scan',
                'Review system logs'
            ],
            'privilege_escalation': [
                'Apply principle of least privilege',
                'Update and patch systems',
                'Monitor privilege usage',
                'Review user permissions'
            ]
        }
        return mitigations.get(threat_type, [])

    def generate_threat_report(self, detected_threats):
        """Generate comprehensive threat report"""
        severity_count = defaultdict(int)
        category_count = defaultdict(int)
        
        for threat in detected_threats:
            severity_count[threat['severity']] += 1
            category_count[threat['category']] += 1
        
        report = {
            'total_threats': len(detected_threats),
            'severity_distribution': dict(severity_count),
            'threat_categories': dict(category_count),
            'threats': detected_threats,
            'risk_score': self._calculate_risk_score(severity_count)
        }
        
        return report

    def _calculate_risk_score(self, severity_count):
        """Calculate overall risk score (0-100)"""
        score = 0
        score += severity_count.get('critical', 0) * 25
        score += severity_count.get('high', 0) * 15
        score += severity_count.get('medium', 0) * 5
        score += severity_count.get('low', 0) * 1
        
        return min(score, 100)

    def scrape_website(self, url):
        """Scrape website for detailed information including links, images, forms, etc."""
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Set timeout and headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, timeout=10, headers=headers, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract website information
            website_info = {
                'url': url,
                'status_code': response.status_code,
                'title': self._extract_title(soup),
                'headings': self._extract_headings(soup),
                'links': self._extract_links(soup, url),
                'images': self._extract_images(soup, url),
                'forms': self._extract_forms(soup),
                'metadata': self._extract_metadata(soup),
                'summary': {
                    'total_links': len(self._extract_links(soup, url)),
                    'total_images': len(self._extract_images(soup, url)),
                    'total_forms': len(self._extract_forms(soup)),
                    'total_headings': len(self._extract_headings(soup))
                }
            }
            
            return website_info
            
        except requests.exceptions.RequestException as e:
            return {'error': f'Failed to fetch URL: {str(e)}'}
        except Exception as e:
            return {'error': f'Error processing website: {str(e)}'}

    def _extract_title(self, soup):
        """Extract website title"""
        title_tag = soup.find('title')
        return title_tag.get_text(strip=True) if title_tag else 'No title found'

    def _extract_headings(self, soup):
        """Extract all headings (h1-h6) from the page"""
        headings = {}
        for i in range(1, 7):
            tag_name = f'h{i}'
            tags = soup.find_all(tag_name)
            if tags:
                headings[tag_name] = [tag.get_text(strip=True) for tag in tags]
        return headings

    def _extract_links(self, soup, base_url):
        """Extract all links from the page"""
        links = []
        seen = set()
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href:
                # Convert relative URLs to absolute
                absolute_url = urljoin(base_url, href)
                
                # Avoid duplicates
                if absolute_url not in seen:
                    seen.add(absolute_url)
                    links.append({
                        'url': absolute_url,
                        'text': link.get_text(strip=True) or 'No text',
                        'title': link.get('title', '')
                    })
        
        return links

    def _extract_images(self, soup, base_url):
        """Extract all images from the page"""
        images = []
        
        for img in soup.find_all('img'):
            src = img.get('src')
            if src:
                # Convert relative URLs to absolute
                absolute_url = urljoin(base_url, src)
                images.append({
                    'src': absolute_url,
                    'alt': img.get('alt', 'No alt text'),
                    'title': img.get('title', ''),
                    'width': img.get('width', ''),
                    'height': img.get('height', '')
                })
        
        return images

    def _extract_forms(self, soup):
        """Extract all forms and their fields from the page"""
        forms_data = []
        
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', '#'),
                'method': form.get('method', 'GET').upper(),
                'id': form.get('id', ''),
                'name': form.get('name', ''),
                'fields': []
            }
            
            # Extract form fields
            for field in form.find_all(['input', 'textarea', 'select']):
                field_info = {
                    'type': field.name,
                    'input_type': field.get('type', 'text') if field.name == 'input' else field.name,
                    'name': field.get('name', ''),
                    'id': field.get('id', ''),
                    'required': field.has_attr('required'),
                    'placeholder': field.get('placeholder', '')
                }
                
                # For select fields, get options
                if field.name == 'select':
                    options = [opt.get_text(strip=True) for opt in field.find_all('option')]
                    field_info['options'] = options
                
                form_info['fields'].append(field_info)
            
            forms_data.append(form_info)
        
        return forms_data

    def _extract_metadata(self, soup):
        """Extract meta tags and other metadata"""
        metadata = {}
        
        # Extract meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                metadata[name] = content
        
        return metadata
