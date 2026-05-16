from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import sys
from werkzeug.utils import secure_filename
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules
from modules.log_analyzer import LogAnalyzer
from modules.network_scanner import NetworkScanner
from modules.packet_analyzer import PacketAnalyzer
from modules.threat_intelligence import ThreatIntelligence
from modules.auth import auth_bp, token_required

app = Flask(__name__, template_folder='../frontend', static_folder='../frontend/static')
CORS(app)

# Register blueprints
app.register_blueprint(auth_bp)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv', 'json', 'pcap', 'pcapng'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# Initialize analyzers
log_analyzer = LogAnalyzer()
network_scanner = NetworkScanner()
packet_analyzer = PacketAnalyzer()
threat_intelligence = ThreatIntelligence()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify server is running"""
    return jsonify({
        'status': 'online',
        'message': 'Cybercrime Investigation Platform is running',
        'version': '1.0',
        'timestamp': str(__import__('datetime').datetime.now())
    })


# ==================== LOG ANALYSIS ====================
@app.route('/api/analyze-log', methods=['POST'])
@token_required
def analyze_log(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze the log file
        results = log_analyzer.analyze(filepath)
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'analysis': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/log-patterns', methods=['GET'])
@token_required
def get_log_patterns(current_user):
    patterns = log_analyzer.get_supported_patterns()
    return jsonify({'patterns': patterns})


# ==================== NETWORK SCANNING ====================
@app.route('/api/scan-network', methods=['POST'])
@token_required
def scan_network(current_user):
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'basic')
        
        if not target:
            return jsonify({'status': 'error', 'error': 'Target IP/Network required'}), 400
        
        # Validate input
        if not (network_scanner.is_valid_ip(target) or network_scanner.is_valid_network(target)):
            return jsonify({'status': 'error', 'error': 'Invalid IP or Network format'}), 400
        
        results = network_scanner.scan(target, scan_type)
        
        if 'error' in results:
            return jsonify({'status': 'error', 'error': results['error']}), 400
        
        return jsonify({
            'status': 'success',
            'target': target,
            'results': results
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'Server error: {str(e)}'}), 500


@app.route('/api/scan-port', methods=['POST'])
@token_required
def scan_port(current_user):
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        ports = data.get('ports', '1-1000').strip()
        
        if not target:
            return jsonify({'status': 'error', 'error': 'Target IP is required'}), 400
        
        # Validate IP format
        if not network_scanner.is_valid_ip(target):
            return jsonify({'status': 'error', 'error': 'Invalid IP address format'}), 400
        
        results = network_scanner.scan_ports(target, ports)
        
        # Check if scan returned an error
        if 'error' in results:
            return jsonify({'status': 'error', 'error': results['error']}), 400
        
        return jsonify({
            'status': 'success',
            'target': target,
            'results': results
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'Server error: {str(e)}'}), 500


# ==================== PACKET ANALYSIS ====================
@app.route('/api/analyze-packets', methods=['POST'])
@token_required
def analyze_packets(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        filter_type = request.form.get('filter', 'all')
        results = packet_analyzer.analyze_file(filepath, filter_type)
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'analysis': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/capture-packets', methods=['POST'])
def capture_packets():
    try:
        data = request.get_json()
        interface = data.get('interface', None)
        packet_count = int(data.get('count', 10))
        duration = int(data.get('duration', 30))
        
        # Validate inputs
        if packet_count < 1 or packet_count > 10000:
            packet_count = 100
        if duration < 1 or duration > 600:
            duration = 30
        
        results = packet_analyzer.capture_live(interface, packet_count, duration)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/packet-interfaces', methods=['GET'])
def get_packet_interfaces():
    try:
        interfaces = packet_analyzer.get_network_interfaces()
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== THREAT INTELLIGENCE ====================
@app.route('/api/threat-detection', methods=['POST'])
@token_required
def threat_detection(current_user):
    try:
        data = request.get_json()
        log_data = data.get('logs', [])
        network_data = data.get('network', {})
        
        threats = threat_intelligence.detect_threats(log_data, network_data)
        
        return jsonify({
            'status': 'success',
            'threats': threats if threats else {'message': 'No threats detected'}
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'Server error: {str(e)}'}), 500


@app.route('/api/threat-analysis/<threat_type>', methods=['GET'])
@token_required
def threat_analysis(current_user, threat_type):
    try:
        if not threat_type or threat_type.strip() == '':
            return jsonify({'status': 'error', 'error': 'Threat type is required'}), 400
        
        analysis = threat_intelligence.get_threat_analysis(threat_type.lower())
        
        if not analysis:
            return jsonify({'status': 'error', 'error': f'Unknown threat type: {threat_type}'}), 404
        
        return jsonify({
            'status': 'success',
            'threat_type': threat_type,
            'analysis': analysis
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'Server error: {str(e)}'}), 500


@app.route('/api/check-ip-reputation', methods=['POST'])
@token_required
def check_ip_reputation(current_user):
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        
        if not ip:
            return jsonify({'status': 'error', 'error': 'IP address is required'}), 400
        
        if not network_scanner.is_valid_ip(ip):
            return jsonify({'status': 'error', 'error': 'Invalid IP address format'}), 400
        
        reputation = threat_intelligence.check_ip_reputation(ip)
        
        return jsonify({
            'status': 'success',
            'ip': ip,
            'reputation': reputation
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'Server error: {str(e)}'}), 500


@app.route('/api/scrape-website', methods=['POST'])
@token_required
def scrape_website(current_user):
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'status': 'error', 'error': 'URL is required'}), 400
        
        website_info = threat_intelligence.scrape_website(url)
        
        if 'error' in website_info:
            return jsonify({
                'status': 'error',
                'error': website_info['error']
            }), 400
        
        return jsonify({
            'status': 'success',
            'url': url,
            'data': website_info
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'Server error: {str(e)}'}), 500


# ==================== DASHBOARD ====================
@app.route('/api/dashboard-stats', methods=['GET'])
@token_required
def dashboard_stats(current_user):
    try:
        stats = {
            'total_logs_processed': 0,
            'threats_detected': 0,
            'networks_scanned': 0,
            'packets_analyzed': 0
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-interfaces', methods=['GET'])
@token_required
def get_network_interfaces(current_user):
    try:
        interfaces = network_scanner.get_interfaces()
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
