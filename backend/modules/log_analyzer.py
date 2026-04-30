import re
from collections import defaultdict, Counter
from datetime import datetime
import json


class LogAnalyzer:
    def __init__(self):
        self.patterns = {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'failed_login': r'(failed|denied|unauthorized|rejected)',
            'error': r'(error|exception|fatal|critical)',
            'warning': r'(warning|warn)',
            'success': r'(success|successful|accepted|connected)',
            'sql_injection': r"(union|select|insert|delete|drop|update|exec|script|alert)",
            'xss_attack': r"(<script|javascript:|onerror|onload|&#)",
            'port_scan': r'(port\s*scan|syn|scanning)',
            'brute_force': r'(brute|force|attempt|trying)',
            'dos_attack': r'(dos|ddos|flood|spike)',
        }
        
        self.threat_indicators = {
            'critical': ['sql_injection', 'xss_attack', 'dos_attack', 'brute_force'],
            'high': ['port_scan', 'failed_login'],
            'medium': ['warning', 'error'],
            'low': ['success']
        }
        
    def analyze(self, filepath):
        """Analyze a log file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return {'error': 'Could not read file'}
        
        results = {
            'total_lines': len(lines),
            'matched_patterns': defaultdict(int),
            'threat_levels': defaultdict(int),
            'unique_ips': set(),
            'failed_logins': [],
            'errors_found': [],
            'suspicious_activity': []
        }
        
        for line in lines:
            if not line.strip():
                continue
            
            # Match patterns
            for pattern_name, pattern in self.patterns.items():
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    results['matched_patterns'][pattern_name] += len(matches)
                    
                    # Classify threat level
                    for threat_level, patterns in self.threat_indicators.items():
                        if pattern_name in patterns:
                            results['threat_levels'][threat_level] += 1
                            
                            if threat_level in ['critical', 'high']:
                                results['suspicious_activity'].append({
                                    'type': pattern_name,
                                    'line': line[:100],
                                    'severity': threat_level
                                })
            
            # Extract IPs
            ips = re.findall(self.patterns['ip_address'], line)
            results['unique_ips'].update(ips)
            
            # Extract failed logins
            if re.search(self.patterns['failed_login'], line, re.IGNORECASE):
                results['failed_logins'].append(line[:100])
            
            # Extract errors
            if re.search(self.patterns['error'], line, re.IGNORECASE):
                results['errors_found'].append(line[:100])
        
        # Convert sets to lists
        results['unique_ips'] = list(results['unique_ips'])
        results['matched_patterns'] = dict(results['matched_patterns'])
        results['threat_levels'] = dict(results['threat_levels'])
        
        # Statistics
        results['stats'] = {
            'total_unique_ips': len(results['unique_ips']),
            'total_failed_logins': len(results['failed_logins']),
            'total_errors': len(results['errors_found']),
            'suspicious_activities': len(results['suspicious_activity']),
            'threat_percentage': round(
                (results['threat_levels'].get('critical', 0) + 
                 results['threat_levels'].get('high', 0)) / len(lines) * 100, 2
            ) if lines else 0
        }
        
        return results

    def get_supported_patterns(self):
        """Return supported analysis patterns"""
        return {
            'pattern': list(self.patterns.keys()),
            'threat_levels': self.threat_indicators
        }

    def analyze_csv(self, filepath):
        """Analyze CSV log files"""
        try:
            import csv
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            results = {
                'total_rows': len(rows),
                'columns': rows[0].keys() if rows else [],
                'data': rows[:100]  # Return first 100 rows
            }
            return results
        except Exception as e:
            return {'error': str(e)}

    def analyze_json(self, filepath):
        """Analyze JSON log files"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                return {
                    'total_rows': len(data),
                    'data': data[:50]
                }
            else:
                return {'data': data}
        except Exception as e:
            return {'error': str(e)}
