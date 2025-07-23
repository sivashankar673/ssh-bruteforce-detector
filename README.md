# 🛡️ SSH Brute Force Detection Script

A powerful Python-based cybersecurity tool for detecting SSH brute force attacks by analyzing authentication logs. This script identifies suspicious IP addresses attempting multiple failed login attempts within configurable time windows.

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Testing](#-testing)
- [Output Formats](#-output-formats)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- **🔍 Multi-Pattern Detection**: Detects various SSH failure types including:
  - Failed password attempts
  - Authentication failures
  - Invalid user attempts
  - Connection anomalies

- **⏱️ Configurable Time Windows**: Set custom thresholds and time windows for attack detection

- **📊 Severity Classification**: Automatically categorizes attacks as LOW, MEDIUM, HIGH, or CRITICAL

- **📁 Multiple Export Formats**: 
  - Console output with colored results
  - CSV export for spreadsheet analysis
  - JSON export for programmatic processing

- **🚫 IP Blocking Commands**: Generates firewall rules for:
  - iptables
  - ufw (Uncomplicated Firewall)
  - hosts.deny

- **🎯 Zero Dependencies**: Uses only Python standard library modules

## 🔧 Requirements

- **Python 3.6+** (tested on Python 3.7-3.11)
- **Read access** to authentication logs (typically `/var/log/auth.log`)
- **Optional**: Root privileges for accessing system logs

## 📥 Installation

### Method 1: Clone Repository
```bash
git clone https://github.com/yourusername/ssh-bruteforce-detector.git
cd ssh-bruteforce-detector
chmod +x bruteforce_detector.py
```

### Method 2: Direct Download
```bash
wget https://raw.githubusercontent.com/yourusername/ssh-bruteforce-detector/main/bruteforce_detector.py
chmod +x bruteforce_detector.py
```

### Method 3: Install Development Dependencies (Optional)
```bash
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Usage
```bash
# Analyze default auth.log with default settings
python3 bruteforce_detector.py

# Analyze specific log file
python3 bruteforce_detector.py -f /var/log/auth.log
```

### Advanced Usage
```bash
# Custom threshold and time window
python3 bruteforce_detector.py -t 10 -w 600

# Export results to CSV
python3 bruteforce_detector.py --csv suspicious_ips.csv

# Export to JSON and generate iptables commands
python3 bruteforce_detector.py --json results.json --block iptables

# Test with sample data
python3 bruteforce_detector.py -f sample_auth.log -t 3 -w 60
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file` | Path to authentication log file | `/var/log/auth.log` |
| `-t, --threshold` | Failed attempts to trigger alert | `5` |
| `-w, --window` | Time window in seconds | `300` (5 minutes) |
| `--csv FILE` | Export results to CSV file | None |
| `--json FILE` | Export results to JSON file | None |
| `--block {iptables,ufw,hosts.deny}` | Generate blocking commands | None |
| `-v, --verbose` | Enable verbose output | False |
| `--version` | Show version information | - |

## 🔍 How It Works

### 1. Log Parsing
The script uses sophisticated regex patterns to extract information from different types of SSH authentication failures:

```python
# Example patterns for different failure types:
'failed_password': r'Failed password for (?:invalid user\s+)?(\S+)\s+from (\d+\.\d+\.\d+\.\d+)'
'auth_failure': r'pam_unix\(sshd:auth\):\s+authentication\s+failure;.*?rhost=(\d+\.\d+\.\d+\.\d+)'
'invalid_user': r'Invalid user (\S+)\s+from (\d+\.\d+\.\d+\.\d+)'
```

### 2. Attack Detection Algorithm
1. **Parse timestamps** from syslog format (`Mon DD HH:MM:SS`)
2. **Group attempts** by source IP address
3. **Apply sliding time window** to detect burst patterns
4. **Count attempts** within each time window
5. **Trigger alerts** when threshold is exceeded

### 3. Severity Classification
```
CRITICAL: ≥50 attempts OR ≥10 unique usernames
HIGH:     ≥20 attempts OR ≥5 unique usernames  
MEDIUM:   ≥10 attempts OR ≥3 unique usernames
LOW:      Above threshold but below other levels
```

## 🧪 Testing

### Quick Test with Sample Data
```bash
# Test the script with provided sample data
python3 bruteforce_detector.py -f sample_auth.log -t 3 -w 60

# Expected output: Detection of 3-4 suspicious IP addresses
```

### Sample Log Format
The script works with standard syslog authentication entries:
```
Jan 23 06:25:21 webserver sshd[14740]: Failed password for root from 182.100.67.119 port 58211 ssh2
Jan 23 06:25:23 webserver sshd[14742]: pam_unix(sshd:auth): authentication failure; rhost=192.168.1.100 user=admin
Jan 23 06:25:24 webserver sshd[14744]: Invalid user test from 203.0.113.15 port 33445
```

### Unit Testing (Optional)
```bash
# Install test dependencies
pip install pytest

# Run tests (when available)
pytest tests/
```

## 📊 Output Formats

### Console Output
```
🛡️  BRUTE FORCE ATTACK DETECTION RESULTS
======================================================================
Analysis Time: 2025-01-21T15:30:45
Detection Threshold: 5 attempts
Time Window: 300 seconds

Suspicious IP Addresses Found: 3

[1] 🚨 ATTACK #1 - HIGH SEVERITY
    IP Address: 182.100.67.119
    Total Attempts: 12
    Time Window: 2025-01-23T06:25:21 to 2025-01-23T06:25:34
    Targeted Usernames: root, admin
    Most Attempted Users: {'root': 10, 'admin': 2}
    Failure Types: {'failed_password': 10, 'auth_failure': 2}
```

### CSV Export
| ip_address | total_attempts | severity | time_window_start | targeted_usernames | most_attempted_user |
|------------|---------------|----------|-------------------|-------------------|-------------------|
| 182.100.67.119 | 12 | HIGH | 2025-01-23T06:25:21 | root, admin | root (10 times) |

### JSON Export
```json
{
  "suspicious_ips": [
    {
      "ip_address": "182.100.67.119",
      "total_attempts": 12,
      "severity": "HIGH",
      "time_window_start": "2025-01-23T06:25:21",
      "time_window_end": "2025-01-23T06:25:34",
      "targeted_usernames": ["root", "admin"],
      "username_attempts": {"root": 10, "admin": 2},
      "failure_types": {"failed_password": 10, "auth_failure": 2}
    }
  ],
  "total_suspicious_ips": 1,
  "analysis_time": "2025-01-21T15:30:45",
  "parameters": {
    "threshold": 5,
    "time_window_seconds": 300
  }
}
```

## 🔒 Security Considerations

### Permissions
- Script requires **read access** to authentication logs
- Typically requires `sudo` for `/var/log/auth.log`
- Consider creating a dedicated user with log read permissions

### Log Rotation
- Large log files may impact performance
- Consider using `logrotate` for log management
- Script handles file encoding errors gracefully

### False Positives
- **Legitimate users** with forgotten passwords may trigger alerts
- **Shared accounts** may generate multiple failures
- **Network issues** can cause connection failures
- **Adjust thresholds** based on your environment

### Integration with Security Tools
```bash
# Integration with fail2ban
# Add custom filter in /etc/fail2ban/filter.d/

# Integration with SIEM
# Use JSON export for log ingestion

# Automated blocking (use with caution)
python3 bruteforce_detector.py --block iptables > block_ips.sh
# Review commands before executing!
```

## 🚀 Optional Features & Improvements

### Feature Roadmap
- [ ] **Real-time monitoring** with file watching
- [ ] **Email/Slack notifications** for critical alerts
- [ ] **Geolocation lookup** for IP addresses
- [ ] **Whitelist support** for trusted IP ranges
- [ ] **Database storage** for historical analysis
- [ ] **Web dashboard** for visualization
- [ ] **Machine learning** for adaptive thresholds

### Performance Optimizations
- [ ] **Streaming parser** for large log files
- [ ] **Multi-threading** for faster processing
- [ ] **Memory optimization** for long-running analysis
- [ ] **Incremental processing** for continuous monitoring

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/yourusername/ssh-bruteforce-detector.git
cd ssh-bruteforce-detector

# Install development dependencies
pip install -r requirements.txt

# Run linting
flake8 bruteforce_detector.py

# Run type checking
mypy bruteforce_detector.py

# Format code
black bruteforce_detector.py
```

### Reporting Issues
- Use GitHub Issues for bug reports
- Include sample log entries (anonymized)
- Provide system information (OS, Python version)
- Describe expected vs actual behavior

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Fail2ban Project** - Inspiration for brute force detection
- **OSSEC/Wazuh** - Log analysis techniques
- **Security Community** - Best practices and regex patterns

## 📞 Support & Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/ssh-bruteforce-detector/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/ssh-bruteforce-detector/wiki)
  
---

**⚠️ Disclaimer**: This tool is for educational and legitimate security purposes only. Always ensure you have proper authorization before analyzing log files or implementing IP blocking rules. The authors are not responsible for misuse of this tool.

**🔗 Related Projects**: 
- [Fail2ban](https://github.com/fail2ban/fail2ban) - Intrusion prevention framework
- [OSSEC](https://github.com/ossec/ossec-hids) - Host-based intrusion detection system
- [DenyHosts](http://denyhosts.sourceforge.net/) - SSH brute force protection

Made with ❤️ for the cybersecurity community
