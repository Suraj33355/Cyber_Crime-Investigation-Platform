# Cybercrime Investigation Platform

A comprehensive web-based platform designed for cybercrime investigation and threat analysis. This application provides tools for log analysis, network scanning, packet analysis, and threat intelligence gathering.

## Features

### 🔍 Log Analysis
- Analyze server logs and system event logs
- Pattern recognition for suspicious activities
- Support for multiple log formats (txt, csv, json, log)
- Threat detection and anomaly identification

### 🌐 Network Scanning
- Comprehensive network reconnaissance
- Port scanning and service detection
- Network topology mapping
- Basic and advanced scan modes

### 📦 Packet Analysis
- Capture and analyze network packets
- Support for PCAP and PCAPng file formats
- Protocol analysis and traffic inspection
- Network behavior profiling

### 🎯 Threat Intelligence
- IP reputation lookup
- Domain analysis
- Threat indicator correlation
- Risk assessment and scoring

### 📊 Dashboard
- Real-time statistics and metrics
- Visual command center
- Investigation tracking
- System status monitoring

## Project Structure

```
cybercrime/
├── backend/
│   ├── app.py                 # Flask application entry point
│   ├── modules/
│   │   ├── log_analyzer.py    # Log analysis module
│   │   ├── network_scanner.py # Network scanning module
│   │   ├── packet_analyzer.py # Packet analysis module
│   │   └── threat_intelligence.py # Threat intelligence module
│   └── uploads/               # File upload directory (auto-created)
├── frontend/
│   ├── index.html            # Main HTML interface
│   └── static/
│       ├── script.js         # Frontend JavaScript
│       └── style.css         # Styling
└── requirements.txt          # Python dependencies
```

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Suraj33355/Cyber_Crime-Investigation-Platform.git
   cd cybercrime
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate
   
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. **Start the Flask backend:**
   ```bash
   cd backend
   python app.py
   ```

2. **Open the web interface:**
   - Navigate to `http://localhost:5000` in your web browser
   - The dashboard will load automatically

## API Endpoints

### Health Check
- **GET** `/api/health` - Server status verification

### Log Analysis
- **POST** `/api/analyze-log` - Analyze uploaded log files
- **GET** `/api/log-patterns` - Get supported log patterns

### Network Scanning
- **POST** `/api/scan-network` - Perform network scans
- **GET** `/api/scan-results` - Retrieve scan results

### Packet Analysis
- **POST** `/api/analyze-packets` - Analyze packet captures
- **GET** `/api/packet-summary` - Get packet analysis summary

### Threat Intelligence
- **POST** `/api/threat-analysis` - Perform threat analysis
- **GET** `/api/ip-reputation` - Check IP reputation

## Supported File Formats

- **Logs:** `.log`, `.txt`, `.csv`, `.json`
- **Packets:** `.pcap`, `.pcapng`
- **Max file size:** 50MB

## Technologies Used

- **Backend:** Flask, Flask-CORS, Werkzeug
- **Network Tools:** Scapy
- **Data Processing:** BeautifulSoup4, Pydantic, Requests
- **File Handling:** python-docx, openpyxl
- **Frontend:** HTML5, CSS3, JavaScript

## Configuration

Key settings in `backend/app.py`:
- `UPLOAD_FOLDER` - Directory for file uploads (default: `uploads/`)
- `MAX_CONTENT_LENGTH` - Maximum upload file size (default: 50MB)
- `ALLOWED_EXTENSIONS` - Accepted file types

## Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Security Notes

⚠️ **Important:** This application is designed for authorized cybercrime investigation use only. Ensure you have proper authorization before using this tool for network scanning or traffic analysis.

## Future Enhancements

- [ ] Database integration for result persistence
- [ ] Advanced AI-based threat detection
- [ ] Real-time alert system
- [ ] Report generation and export
- [ ] Multi-user authentication
- [ ] Historical data tracking

## Contributing

Contributions are welcome! Please feel free to submit pull requests or report issues.

## License

This project is provided as-is for educational and authorized investigation purposes.

## Contact

For questions or support, please contact the project owner.

---

**Last Updated:** April 30, 2026