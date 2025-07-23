#!/usr/bin/env python3
"""
Brute Force Detection Script
Author: Security Team
Description: Detects SSH brute force attacks by analyzing authentication logs
"""

import re
import argparse
import csv
import json
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
import time

class BruteForceDetector:
    """
    SSH Brute Force Attack Detection System

    This class analyzes authentication logs to identify potential brute force attacks
    by tracking failed login attempts from IP addresses within specified time windows.
    """

    def __init__(self, threshold: int = 5, time_window: int = 300, log_file: str = "/var/log/auth.log"):
        """
        Initialize the brute force detector

        Args:
            threshold (int): Number of failed attempts to trigger alert (default: 5)
            time_window (int): Time window in seconds for counting attempts (default: 300s/5min)
            log_file (str): Path to authentication log file
        """
        self.threshold = threshold
        self.time_window = time_window
        self.log_file = log_file

        # Regex patterns for different SSH failure types
        self.patterns = {
            'failed_password': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
                r'(\S+)\s+'                                    # hostname
                r'sshd\[(\d+)\]:\s+'                          # process[pid]
                r'Failed password for (?:invalid user\s+)?(\S+)\s+'  # username
                r'from (\d+\.\d+\.\d+\.\d+)\s+'               # IP address
                r'port (\d+)\s+'                              # port
                r'(\S+)'                                       # protocol
            ),
            'auth_failure': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
                r'(\S+)\s+'                                    # hostname
                r'sshd\[(\d+)\]:\s+'                          # process[pid]
                r'pam_unix\(sshd:auth\):\s+authentication\s+failure;.*?'
                r'rhost=(\d+\.\d+\.\d+\.\d+)(?:\s+user=(\S+))?'  # IP and optional user
            ),
            'invalid_user': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
                r'(\S+)\s+'                                    # hostname
                r'sshd\[(\d+)\]:\s+'                          # process[pid]
                r'Invalid user (\S+)\s+'                      # username
                r'from (\d+\.\d+\.\d+\.\d+)'                  # IP address
            ),
            'connection_closed': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
                r'(\S+)\s+'                                    # hostname
                r'sshd\[(\d+)\]:\s+'                          # process[pid]
                r'Connection closed by (\d+\.\d+\.\d+\.\d+)'  # IP address
            )
        }

        # Storage for tracking attempts
        self.failed_attempts = defaultdict(list)
        self.suspicious_ips = set()
        self.detected_attacks = []

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse syslog timestamp format to datetime object

        Args:
            timestamp_str (str): Timestamp in format "Mon DD HH:MM:SS"

        Returns:
            datetime: Parsed datetime object (assumes current year)
        """
        try:
            # Add current year since syslog doesn't include it
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            # Fallback to current time if parsing fails
            return datetime.now()

    def extract_failed_login(self, line: str) -> Optional[Tuple[datetime, str, str, str]]:
        """
        Extract failed login information from log line

        Args:
            line (str): Log file line

        Returns:
            Optional[Tuple]: (timestamp, ip, username, failure_type) or None
        """
        # Try failed password pattern
        match = self.patterns['failed_password'].search(line)
        if match:
            timestamp_str, hostname, pid, username, ip, port, protocol = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            return (timestamp, ip, username, "failed_password")

        # Try authentication failure pattern
        match = self.patterns['auth_failure'].search(line)
        if match:
            timestamp_str, hostname, pid, ip, username = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            username = username or "unknown"
            return (timestamp, ip, username, "auth_failure")

        # Try invalid user pattern
        match = self.patterns['invalid_user'].search(line)
        if match:
            timestamp_str, hostname, pid, username, ip = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            return (timestamp, ip, username, "invalid_user")

        return None

    def is_within_time_window(self, timestamp: datetime, window_start: datetime) -> bool:
        """
        Check if timestamp is within the specified time window

        Args:
            timestamp (datetime): Event timestamp
            window_start (datetime): Start of time window

        Returns:
            bool: True if within window
        """
        return (timestamp - window_start).total_seconds() <= self.time_window

    def analyze_log_file(self) -> Dict:
        """
        Analyze the log file for brute force attacks

        Returns:
            Dict: Analysis results
        """
        print(f"[INFO] Analyzing log file: {self.log_file}")
        print(f"[INFO] Detection parameters: threshold={self.threshold}, time_window={self.time_window}s")

        if not os.path.exists(self.log_file):
            print(f"[ERROR] Log file not found: {self.log_file}")
            return {"error": "Log file not found", "suspicious_ips": []}

        total_lines = 0
        failed_logins = 0

        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    total_lines += 1

                    # Extract failed login attempt
                    result = self.extract_failed_login(line)
                    if result:
                        timestamp, ip, username, failure_type = result
                        failed_logins += 1

                        # Store the attempt
                        self.failed_attempts[ip].append({
                            'timestamp': timestamp,
                            'username': username,
                            'failure_type': failure_type
                        })

        except Exception as e:
            print(f"[ERROR] Error reading log file: {e}")
            return {"error": str(e), "suspicious_ips": []}

        print(f"[INFO] Processed {total_lines} log lines")
        print(f"[INFO] Found {failed_logins} failed login attempts")

        # Analyze for brute force patterns
        return self._detect_brute_force_attacks()

    def _detect_brute_force_attacks(self) -> Dict:
        """
        Detect brute force attacks from collected failed attempts

        Returns:
            Dict: Detection results
        """
        current_time = datetime.now()
        results = {
            'suspicious_ips': [],
            'total_suspicious_ips': 0,
            'analysis_time': current_time.isoformat(),
            'parameters': {
                'threshold': self.threshold,
                'time_window_seconds': self.time_window
            }
        }

        print(f"\n[INFO] Analyzing failed attempts for brute force patterns...")

        for ip, attempts in self.failed_attempts.items():
            # Sort attempts by timestamp
            sorted_attempts = sorted(attempts, key=lambda x: x['timestamp'])

            # Check for patterns within time windows
            for i, base_attempt in enumerate(sorted_attempts):
                window_start = base_attempt['timestamp']
                window_attempts = []

                # Collect all attempts within time window
                for j in range(i, len(sorted_attempts)):
                    attempt = sorted_attempts[j]
                    if self.is_within_time_window(attempt['timestamp'], window_start):
                        window_attempts.append(attempt)
                    else:
                        break

                # Check if threshold is exceeded
                if len(window_attempts) >= self.threshold:
                    # Extract attack details
                    usernames = [att['username'] for att in window_attempts]
                    failure_types = [att['failure_type'] for att in window_attempts]

                    attack_info = {
                        'ip_address': ip,
                        'total_attempts': len(window_attempts),
                        'time_window_start': window_start.isoformat(),
                        'time_window_end': window_attempts[-1]['timestamp'].isoformat(),
                        'targeted_usernames': list(set(usernames)),
                        'username_attempts': dict(Counter(usernames)),
                        'failure_types': dict(Counter(failure_types)),
                        'severity': self._calculate_severity(len(window_attempts), len(set(usernames)))
                    }

                    results['suspicious_ips'].append(attack_info)
                    self.suspicious_ips.add(ip)
                    break  # Move to next IP

        results['total_suspicious_ips'] = len(results['suspicious_ips'])

        # Sort by severity and attempt count
        results['suspicious_ips'].sort(key=lambda x: (x['severity'], x['total_attempts']), reverse=True)

        return results

    def _calculate_severity(self, attempt_count: int, unique_usernames: int) -> str:
        """
        Calculate attack severity based on attempt count and username diversity

        Args:
            attempt_count (int): Number of attempts
            unique_usernames (int): Number of unique usernames tried

        Returns:
            str: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if attempt_count >= 50 or unique_usernames >= 10:
            return "CRITICAL"
        elif attempt_count >= 20 or unique_usernames >= 5:
            return "HIGH"
        elif attempt_count >= 10 or unique_usernames >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def print_results(self, results: Dict) -> None:
        """
        Print analysis results to console

        Args:
            results (Dict): Analysis results from analyze_log_file()
        """
        if 'error' in results:
            print(f"\n[ERROR] {results['error']}")
            return

        print(f"\n{'='*70}")
        print(f"🛡️  BRUTE FORCE ATTACK DETECTION RESULTS")
        print(f"{'='*70}")
        print(f"Analysis Time: {results['analysis_time']}")
        print(f"Detection Threshold: {results['parameters']['threshold']} attempts")
        print(f"Time Window: {results['parameters']['time_window_seconds']} seconds")
        print(f"\nSuspicious IP Addresses Found: {results['total_suspicious_ips']}")

        if results['total_suspicious_ips'] == 0:
            print("\n✅ No brute force attacks detected!")
            return

        print(f"\n{'='*70}")
        print(f"DETAILED ATTACK ANALYSIS")
        print(f"{'='*70}")

        for i, attack in enumerate(results['suspicious_ips'], 1):
            severity_emoji = {
                'LOW': '🟡',
                'MEDIUM': '🟠', 
                'HIGH': '🔴',
                'CRITICAL': '🚨'
            }

            print(f"\n[{i}] {severity_emoji.get(attack['severity'], '⚠️')} ATTACK #{i} - {attack['severity']} SEVERITY")
            print(f"    IP Address: {attack['ip_address']}")
            print(f"    Total Attempts: {attack['total_attempts']}")
            print(f"    Time Window: {attack['time_window_start'][:19]} to {attack['time_window_end'][:19]}")
            print(f"    Targeted Usernames: {', '.join(attack['targeted_usernames'])}")
            print(f"    Most Attempted Users: {dict(sorted(attack['username_attempts'].items(), key=lambda x: x[1], reverse=True))}")
            print(f"    Failure Types: {attack['failure_types']}")

    def export_csv(self, results: Dict, output_file: str) -> None:
        """
        Export results to CSV file

        Args:
            results (Dict): Analysis results
            output_file (str): Output CSV file path
        """
        if 'error' in results or results['total_suspicious_ips'] == 0:
            print(f"[INFO] No data to export to CSV")
            return

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['ip_address', 'total_attempts', 'severity', 'time_window_start', 
                             'time_window_end', 'targeted_usernames', 'most_attempted_user', 
                             'failure_types']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for attack in results['suspicious_ips']:
                    # Get most attempted username
                    most_attempted = max(attack['username_attempts'].items(), 
                                       key=lambda x: x[1]) if attack['username_attempts'] else ('N/A', 0)

                    writer.writerow({
                        'ip_address': attack['ip_address'],
                        'total_attempts': attack['total_attempts'],
                        'severity': attack['severity'],
                        'time_window_start': attack['time_window_start'],
                        'time_window_end': attack['time_window_end'],
                        'targeted_usernames': ', '.join(attack['targeted_usernames']),
                        'most_attempted_user': f"{most_attempted[0]} ({most_attempted[1]} times)",
                        'failure_types': ', '.join(f"{k}:{v}" for k, v in attack['failure_types'].items())
                    })

            print(f"[INFO] Results exported to CSV: {output_file}")

        except Exception as e:
            print(f"[ERROR] Failed to export CSV: {e}")

    def export_json(self, results: Dict, output_file: str) -> None:
        """
        Export results to JSON file

        Args:
            results (Dict): Analysis results
            output_file (str): Output JSON file path
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(results, jsonfile, indent=2, default=str)

            print(f"[INFO] Results exported to JSON: {output_file}")

        except Exception as e:
            print(f"[ERROR] Failed to export JSON: {e}")

    def block_ips(self, results: Dict, action: str = "iptables") -> None:
        """
        Generate IP blocking commands (for demonstration - doesn't execute them)

        Args:
            results (Dict): Analysis results
            action (str): Blocking method ('iptables', 'ufw', 'hosts.deny')
        """
        if 'error' in results or results['total_suspicious_ips'] == 0:
            print(f"[INFO] No IPs to block")
            return

        print(f"\n[INFO] Generated IP blocking commands ({action}):")
        print(f"{'='*50}")

        for attack in results['suspicious_ips']:
            ip = attack['ip_address']

            if action == "iptables":
                cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            elif action == "ufw":
                cmd = f"sudo ufw deny from {ip}"
            elif action == "hosts.deny":
                cmd = f"echo 'ALL: {ip}' >> /etc/hosts.deny"
            else:
                cmd = f"# Block {ip} using your preferred firewall method"

            print(f"# Block {ip} (Severity: {attack['severity']}, Attempts: {attack['total_attempts']})")
            print(f"{cmd}")
            print()

        print("[WARNING] These are example commands. Review and test before executing!")
        print("[WARNING] Consider using fail2ban for automated IP blocking.")


def main():
    """
    Main function to handle command line arguments and run the detector
    """

    parser = argparse.ArgumentParser(
        description="SSH Brute Force Attack Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  bruteforce_detector.py                           # Analyze default log file
  bruteforce_detector.py -f /var/log/auth.log -t 10    # Custom threshold
  bruteforce_detector.py -w 600 --csv output.csv       # Custom time window and CSV export
  bruteforce_detector.py --json results.json --block ufw   # JSON export with UFW commands
  bruteforce_detector.py -f sample_auth.log -t 3 -w 60     # Quick test with sample data
        """
    )

    parser.add_argument(
        '-f', '--file',
        default='/var/log/auth.log',
        help='Path to authentication log file (default: /var/log/auth.log)'
    )

    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=5,
        help='Number of failed attempts to trigger alert (default: 5)'
    )

    parser.add_argument(
        '-w', '--window',
        type=int,
        default=300,
        help='Time window in seconds for counting attempts (default: 300)'
    )

    parser.add_argument(
        '--csv',
        metavar='FILE',
        help='Export results to CSV file'
    )

    parser.add_argument(
        '--json',
        metavar='FILE', 
        help='Export results to JSON file'
    )

    parser.add_argument(
        '--block',
        choices=['iptables', 'ufw', 'hosts.deny'],
        help='Generate IP blocking commands (demonstration only)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='bruteforce_detector.py 1.0.0'
    )

    args = parser.parse_args()

    # Create detector instance
    detector = BruteForceDetector(
        threshold=args.threshold,
        time_window=args.window,
        log_file=args.file
    )

    # Analyze the log file
    results = detector.analyze_log_file()

    # Display results
    detector.print_results(results)

    # Export results if requested
    if args.csv:
        detector.export_csv(results, args.csv)

    if args.json:
        detector.export_json(results, args.json)

    # Generate blocking commands if requested
    if args.block:
        detector.block_ips(results, args.block)

    # Exit with appropriate code
    if 'error' in results:
                # ...existing code...
            # Exit with appropriate code
            if not isinstance(results, dict) or 'error' in results:
                sys.exit(1)
            elif results.get('total_suspicious_ips', 0) > 0:
                print(f"\n⚠️  WARNING: {results['total_suspicious_ips']} suspicious IP addresses detected!")
                sys.exit(2)
            else:
                print(f"\n✅ No brute force attacks detected.")
                sys.exit(0)
        # ...existing code...sys.exit(1)
    elif results['total_suspicious_ips'] > 0:
        print(f"\n⚠️  WARNING: {results['total_suspicious_ips']} suspicious IP addresses detected!")
        sys.exit(2)
    else:
        print(f"\n✅ No brute force attacks detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
