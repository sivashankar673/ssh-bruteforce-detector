
# 🚀 Complete Setup Instructions

## Quick Start (Copy & Paste Ready)

### 1. Create Project Directory
```bash
mkdir ssh-bruteforce-detector
cd ssh-bruteforce-detector
```

### 2. Set Execute Permissions
```bash
chmod +x bruteforce_detector.py
chmod +x test_bruteforce_detector.py
```

### 3. Test the Tool
```bash
# Test with sample data
python3 bruteforce_detector.py -f sample_auth.log -t 3 -w 60

# Run comprehensive tests
python3 test_bruteforce_detector.py
```

### 4. Production Usage
```bash
# Analyze real auth logs (requires sudo)
sudo python3 bruteforce_detector.py -f /var/log/auth.log

# Export results to CSV
sudo python3 bruteforce_detector.py --csv attack_report.csv

# Generate IP blocking commands
sudo python3 bruteforce_detector.py --block iptables
```

## 🔧 Development Setup

### Install Development Tools
```bash
pip install flake8 black mypy pytest
```

### Code Quality Checks
```bash
make lint      # Run linting
make format    # Format code
make test      # Run tests
make quality   # All quality checks
```

## 📊 Expected Test Results

When you run the tool with sample data, you should see:
- ✅ Detection of 2-3 suspicious IP addresses
- 🎯 HIGH/MEDIUM severity classifications
- 📈 Multiple failed login patterns identified
- 🚫 IP blocking commands generated

## 🐛 Troubleshooting

### Permission Issues
```bash
# If you get permission errors:
sudo python3 bruteforce_detector.py -f /var/log/auth.log

# Or create a dedicated log reader user:
sudo adduser logread
sudo usermod -a -G adm logread
```

### Python Version Issues
```bash
# Check Python version (needs 3.6+)
python3 --version

# If python3 is not found:
python --version  # Try this instead
```

### Missing Log File
```bash
# Check log file location on your system:
ls -la /var/log/auth.log      # Ubuntu/Debian
ls -la /var/log/secure        # CentOS/RHEL

# Use the correct path:
python3 bruteforce_detector.py -f /var/log/secure
```
