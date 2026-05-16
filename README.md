# Cybercrime Investigation Platform

A comprehensive web-based platform for cybercrime investigation and threat analysis. This platform provides tools for log analysis, network scanning, packet analysis, and threat intelligence to help security professionals investigate and respond to cyber threats.

## Features

### 🔍 Log Analysis
- Parse and analyze system and application logs
- Identify suspicious patterns and security threats
- Detect SQL injection, XSS attacks, and other attack signatures
- Extract and analyze IP addresses from logs
- Categorize threats by severity level (Critical, High, Medium, Low)

### 🌐 Network Scanning
- Perform network reconnaissance and port scanning
- Validate IP addresses and network ranges
- Support for multiple scan types (basic, detailed, etc.)
- Identify active hosts and open ports
- Network vulnerability assessment

### 📦 Packet Analysis
- Analyze captured network packets (PCAP files)
- Filter packets by protocol type
- Extract protocol-level information
- Support for live packet capture
- Real-time network traffic analysis

### 🎯 Threat Intelligence
- Database of known malicious IPs and domains
- Threat signature detection
- Severity level classification
- Security threat indicators
- Pattern matching for attack detection

### 🔐 Authentication & Security
- User authentication with JWT tokens
- Login and signup functionality
- Secure file uploads with validation
- Role-based access control
- Token-based API security

## Tech Stack

### Backend
- **Python 3.x**
- **Flask** - Web framework
- **Scapy** - Packet manipulation and network scanning
- **Flask-CORS** - Cross-Origin Resource Sharing
- **PyJWT** - JWT authentication
- **python-dotenv** - Environment variables management

### Frontend
- **HTML5** - Structure
- **CSS3** - Styling and animations
- **JavaScript** - Interactive functionality

### Dependencies
See [requirements.txt](requirements.txt) for the complete list of Python dependencies.

## Project Structure

```
cybercrime/
├── backend/
│   ├── app.py                 # Main Flask application and API endpoints
│   ├── modules/
│   │   ├── auth.py           # Authentication module
│   │   ├── log_analyzer.py    # Log analysis functionality
│   │   ├── network_scanner.py # Network scanning tools
│   │   ├── packet_analyzer.py # Packet analysis tools
│   │   ├── threat_intelligence.py  # Threat detection and intelligence
│   │   └── __init__.py
│   ├── uploads/              # Directory for uploaded files
│   └── __pycache__/
├── frontend/
│   ├── index.html            # Main HTML file
│   └── static/
│       ├── style.css         # Main stylesheet
│       ├── login.css         # Login page styles
│       ├── script.js         # Main application script
│       └── login.js          # Login functionality
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)
- Windows, macOS, or Linux

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/Suraj33355/Cyber_Crime-Investigation-Platform.git
   cd cybercrime
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**
   
   **Windows:**
   ```bash
   venv\Scripts\activate
   ```
   
   **macOS/Linux:**
   ```bash
   source venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Start the Backend Server

Navigate to the backend directory and run:

```bash
cd backend
python app.py
```

The server will start on `http://localhost:5000` (or the configured port).

### Access the Application

Open your web browser and navigate to:
```
http://localhost:5000
```

You will be presented with the login/signup page. Create an account or login to access the investigation tools.

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/signup` - User registration

### Log Analysis
- `POST /api/analyze-log` - Analyze uploaded log file
- `GET /api/log-patterns` - Get supported log patterns

### Network Scanning
- `POST /api/scan-network` - Scan network for active hosts
- `POST /api/scan-port` - Perform port scanning

### Packet Analysis
- `POST /api/analyze-packets` - Analyze PCAP files
- `POST /api/capture-packets` - Capture live network packets

### System
- `GET /api/health` - Health check endpoint

## Usage Guide

### 1. Login/Signup
- Create a new account or login with existing credentials
- JWT token is generated upon successful authentication

### 2. Analyze Logs
- Upload a log file (supported formats: .log, .txt, .csv, .json)
- The platform analyzes the log for threats and security indicators
- View detailed analysis including threat levels, suspicious IPs, and attack patterns

### 3. Scan Networks
- Enter target IP address or network range
- Select scan type (basic or detailed)
- View active hosts and services running

### 4. Port Scanning
- Specify target IP address
- Define port range (e.g., 1-1000)
- Identify open ports and services

### 5. Analyze Packets
- Upload PCAP/PCAPNG files
- Apply protocol filters if needed
- Review packet details and network communication

## Configuration

### Max Upload File Size
- Default: 50MB
- Modify in `backend/app.py` line 31

### Allowed File Extensions
- Default: `log`, `txt`, `csv`, `json`, `pcap`, `pcapng`
- Modify in `backend/app.py` line 26

## Security Considerations

- Always run the application in a secure environment
- Use strong passwords for user accounts
- Keep dependencies updated
- Review and validate network scanning targets before execution
- Use HTTPS in production environments
- Store JWT secrets securely

## Limitations & Known Issues

- Network scanning requires appropriate permissions
- Some features may require elevated privileges on the system
- Large log files (>50MB) are not supported
- Packet capture requires administrator/root privileges

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Suraj33355**

## Support

For issues, questions, or suggestions, please:
- Open an issue on GitHub
- Contact the project maintainer

## Disclaimer

This tool is intended for authorized security research and cybercrime investigation purposes only. Unauthorized network scanning or system access is illegal. Always obtain proper authorization before conducting any security assessments or investigations.

---

**Last Updated:** May 2026  
**Version:** 1.0  
**Status:** Active Development
