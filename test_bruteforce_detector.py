#!/usr/bin/env python3
'''
Test Script for SSH Brute Force Detection Tool
This script demonstrates how to test the bruteforce_detector.py with sample data
'''

import os
import sys
import subprocess
import tempfile
from datetime import datetime

def create_test_log():
    '''Create a test log file with known attack patterns'''
    # Using string concatenation to avoid f-string issues with timestamps
    lines = [
        'Jan 23 ' + '06:25:18' + ' testserver sshd[14738]: Connection from 192.168.1.100 port 58209 on 192.168.1.10 port 22',
        'Jan 23 ' + '06:25:21' + ' testserver sshd[14740]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100 user=root',
        'Jan 23 ' + '06:25:23' + ' testserver sshd[14740]: Failed password for root from 192.168.1.100 port 58211 ssh2',
        'Jan 23 ' + '06:25:25' + ' testserver sshd[14740]: Failed password for root from 192.168.1.100 port 58211 ssh2',
        'Jan 23 ' + '06:25:27' + ' testserver sshd[14740]: Failed password for root from 192.168.1.100 port 58211 ssh2',
        'Jan 23 ' + '06:25:29' + ' testserver sshd[14740]: Failed password for root from 192.168.1.100 port 58211 ssh2',
        'Jan 23 ' + '06:25:31' + ' testserver sshd[14740]: Failed password for admin from 192.168.1.100 port 58211 ssh2',
        'Jan 23 ' + '06:25:33' + ' testserver sshd[14742]: Failed password for invalid user test from 10.0.0.50 port 63605 ssh2',
        'Jan 23 ' + '06:25:35' + ' testserver sshd[14744]: Failed password for invalid user guest from 10.0.0.50 port 63607 ssh2',
        'Jan 23 ' + '06:25:37' + ' testserver sshd[14746]: Failed password for invalid user oracle from 10.0.0.50 port 63609 ssh2',
        'Jan 23 ' + '06:25:39' + ' testserver sshd[14748]: Failed password for invalid user mysql from 10.0.0.50 port 63611 ssh2',
        'Jan 23 ' + '06:25:41' + ' testserver sshd[14750]: Failed password for invalid user postgres from 10.0.0.50 port 63613 ssh2',
        'Jan 23 ' + '06:26:15' + ' testserver sshd[14752]: Accepted password for user1 from 192.168.1.25 port 54321 ssh2',
        'Jan 23 ' + '06:26:30' + ' testserver sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/ls'
    ]

    test_log_content = '\n'.join(lines) + '\n'

    # Create temporary test log file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(test_log_content)
        return f.name

def run_test(test_name, command, expected_result=None):
    '''Run a test case and report results'''
    print(f"\n{'='*60}")
    print(f"🧪 Running Test: {test_name}")
    print(f"{'='*60}")
    print(f"Command: {' '.join(command)}")

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)

        print(f"\n📊 Exit Code: {result.returncode}")
        print(f"\n📝 Output:")
        print(result.stdout)

        if result.stderr:
            print(f"\n⚠️  Errors:")
            print(result.stderr)

        # Check expected result
        if expected_result:
            if expected_result in result.stdout:
                print(f"\n✅ Test PASSED: Expected result found")
                return True
            else:
                print(f"\n❌ Test FAILED: Expected result not found")
                return False

        print(f"\n✅ Test COMPLETED")
        return True

    except subprocess.TimeoutExpired:
        print(f"\n⏰ Test TIMEOUT: Command took too long")
        return False
    except Exception as e:
        print(f"\n💥 Test ERROR: {e}")
        return False

def main():
    '''Run comprehensive tests of the brute force detection tool'''
    print("🛡️  SSH Brute Force Detection Tool - Test Suite")
    print("=" * 60)

    # Check if main script exists
    if not os.path.exists('bruteforce_detector.py'):
        print("❌ Error: bruteforce_detector.py not found!")
        print("Please run this test from the project directory.")
        sys.exit(1)

    # Create test log file
    test_log_file = create_test_log()
    print(f"✅ Created test log file: {test_log_file}")

    # Test cases
    tests = [
        {
            "name": "Help Command",
            "command": ["python3", "bruteforce_detector.py", "--help"],
            "expected": "SSH Brute Force Attack Detection Tool"
        },
        {
            "name": "Version Command", 
            "command": ["python3", "bruteforce_detector.py", "--version"],
            "expected": "1.0.0"
        },
        {
            "name": "Basic Detection with Sample Data",
            "command": ["python3", "bruteforce_detector.py", "-f", test_log_file, "-t", "3"],
            "expected": "suspicious IP addresses detected"
        },
        {
            "name": "CSV Export Test",
            "command": ["python3", "bruteforce_detector.py", "-f", test_log_file, "-t", "3", "--csv", "test_output.csv"],
            "expected": "Results exported to CSV"
        },
        {
            "name": "JSON Export Test", 
            "command": ["python3", "bruteforce_detector.py", "-f", test_log_file, "-t", "3", "--json", "test_output.json"],
            "expected": "Results exported to JSON"
        },
        {
            "name": "IP Blocking Commands",
            "command": ["python3", "bruteforce_detector.py", "-f", test_log_file, "-t", "3", "--block", "iptables"],
            "expected": "sudo iptables"
        },
        {
            "name": "Custom Time Window",
            "command": ["python3", "bruteforce_detector.py", "-f", test_log_file, "-t", "2", "-w", "120"],
            "expected": "BRUTE FORCE ATTACK DETECTION RESULTS"
        },
        {
            "name": "Non-existent Log File",
            "command": ["python3", "bruteforce_detector.py", "-f", "/nonexistent/file.log"],
            "expected": "Log file not found"
        }
    ]

    # Run all tests
    passed = 0
    failed = 0

    for test in tests:
        if run_test(test["name"], test["command"], test.get("expected")):
            passed += 1
        else:
            failed += 1

    # Test results summary
    print(f"\n\n{'='*60}")
    print(f"📋 TEST SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📊 Total: {passed + failed}")

    if failed == 0:
        print(f"\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review the output above.")

    # Cleanup
    try:
        os.unlink(test_log_file)
        print(f"\n🧹 Cleaned up test log file")
    except:
        pass

    # Cleanup output files
    for file in ["test_output.csv", "test_output.json"]:
        try:
            if os.path.exists(file):
                os.unlink(file)
                print(f"🧹 Cleaned up {file}")
        except:
            pass

    print(f"\n{'='*60}")
    print(f"🏁 Test suite completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Exit with proper code
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
