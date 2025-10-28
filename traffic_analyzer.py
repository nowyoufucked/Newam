#!/usr/bin/env python3
"""
Traffic Analyzer
================
Analyze captured HTTP/HTTPS traffic from HAR files.

Provides insights on:
- Request patterns
- Response times
- Status code distributions
- Data transfer statistics
- Top domains and endpoints
"""

import json
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from urllib.parse import urlparse


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class TrafficAnalyzer:
    """Analyze HTTP traffic from HAR files"""

    def __init__(self, har_file):
        self.har_file = har_file
        self.data = None
        self.entries = []

    def load(self):
        """Load HAR file"""
        try:
            with open(self.har_file, 'r') as f:
                self.data = json.load(f)
            self.entries = self.data.get('log', {}).get('entries', [])
            return True
        except Exception as e:
            print(f"{Colors.FAIL}Error loading HAR file: {e}{Colors.ENDC}")
            return False

    def analyze_methods(self):
        """Analyze HTTP methods"""
        methods = Counter()
        for entry in self.entries:
            method = entry.get('request', {}).get('method', 'UNKNOWN')
            methods[method] += 1
        return methods

    def analyze_status_codes(self):
        """Analyze HTTP status codes"""
        status_codes = Counter()
        for entry in self.entries:
            status = entry.get('response', {}).get('status', 0)
            status_codes[status] += 1
        return status_codes

    def analyze_domains(self):
        """Analyze domains"""
        domains = Counter()
        for entry in self.entries:
            url = entry.get('request', {}).get('url', '')
            domain = urlparse(url).netloc
            if domain:
                domains[domain] += 1
        return domains

    def analyze_endpoints(self):
        """Analyze endpoints (path patterns)"""
        endpoints = Counter()
        for entry in self.entries:
            url = entry.get('request', {}).get('url', '')
            parsed = urlparse(url)
            endpoint = f"{parsed.netloc}{parsed.path}"
            if endpoint:
                endpoints[endpoint] += 1
        return endpoints

    def analyze_response_times(self):
        """Analyze response times"""
        times = []
        for entry in self.entries:
            time_ms = entry.get('time', 0)
            if time_ms > 0:
                times.append(time_ms)

        if not times:
            return None

        return {
            'min': min(times),
            'max': max(times),
            'avg': sum(times) / len(times),
            'total': sum(times),
            'count': len(times)
        }

    def analyze_data_transfer(self):
        """Analyze data transfer"""
        total_sent = 0
        total_received = 0

        for entry in self.entries:
            req_body_size = entry.get('request', {}).get('bodySize', 0)
            resp_body_size = entry.get('response', {}).get('bodySize', 0)

            if req_body_size > 0:
                total_sent += req_body_size
            if resp_body_size > 0:
                total_received += resp_body_size

        return {
            'sent': total_sent,
            'received': total_received,
            'total': total_sent + total_received
        }

    def analyze_content_types(self):
        """Analyze content types"""
        content_types = Counter()
        for entry in self.entries:
            headers = entry.get('response', {}).get('headers', [])
            for header in headers:
                if header.get('name', '').lower() == 'content-type':
                    ct = header.get('value', '').split(';')[0].strip()
                    if ct:
                        content_types[ct] += 1
                    break
        return content_types

    def find_slow_requests(self, threshold=1000):
        """Find requests slower than threshold (ms)"""
        slow_requests = []
        for entry in self.entries:
            time_ms = entry.get('time', 0)
            if time_ms > threshold:
                url = entry.get('request', {}).get('url', '')
                method = entry.get('request', {}).get('method', '')
                status = entry.get('response', {}).get('status', 0)
                slow_requests.append({
                    'method': method,
                    'url': url,
                    'time': time_ms,
                    'status': status
                })
        return sorted(slow_requests, key=lambda x: x['time'], reverse=True)

    def find_errors(self):
        """Find requests with error status codes (4xx, 5xx)"""
        errors = []
        for entry in self.entries:
            status = entry.get('response', {}).get('status', 0)
            if status >= 400:
                url = entry.get('request', {}).get('url', '')
                method = entry.get('request', {}).get('method', '')
                status_text = entry.get('response', {}).get('statusText', '')
                errors.append({
                    'method': method,
                    'url': url,
                    'status': status,
                    'status_text': status_text
                })
        return errors

    def print_report(self):
        """Print comprehensive analysis report"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}TRAFFIC ANALYSIS REPORT{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"File: {self.har_file}")
        print(f"Total Entries: {len(self.entries)}")

        # HTTP Methods
        print(f"\n{Colors.OKBLUE}HTTP METHODS{Colors.ENDC}")
        methods = self.analyze_methods()
        for method, count in methods.most_common():
            print(f"  {method:10s}: {count:5d} ({count/len(self.entries)*100:.1f}%)")

        # Status Codes
        print(f"\n{Colors.OKBLUE}STATUS CODES{Colors.ENDC}")
        status_codes = self.analyze_status_codes()
        for status, count in sorted(status_codes.items()):
            if status < 300:
                color = Colors.OKGREEN
            elif status < 400:
                color = Colors.OKCYAN
            else:
                color = Colors.FAIL
            print(f"  {color}{status:3d}: {count:5d} ({count/len(self.entries)*100:.1f}%){Colors.ENDC}")

        # Response Times
        print(f"\n{Colors.OKBLUE}RESPONSE TIMES{Colors.ENDC}")
        times = self.analyze_response_times()
        if times:
            print(f"  Min:     {times['min']:8.2f} ms")
            print(f"  Max:     {times['max']:8.2f} ms")
            print(f"  Average: {times['avg']:8.2f} ms")
            print(f"  Total:   {times['total']:8.2f} ms")
        else:
            print("  No timing data available")

        # Data Transfer
        print(f"\n{Colors.OKBLUE}DATA TRANSFER{Colors.ENDC}")
        transfer = self.analyze_data_transfer()
        print(f"  Sent:     {transfer['sent']:10,} bytes ({transfer['sent']/1024:.2f} KB)")
        print(f"  Received: {transfer['received']:10,} bytes ({transfer['received']/1024:.2f} KB)")
        print(f"  Total:    {transfer['total']:10,} bytes ({transfer['total']/1024:.2f} KB)")

        # Top Domains
        print(f"\n{Colors.OKBLUE}TOP DOMAINS{Colors.ENDC}")
        domains = self.analyze_domains()
        for domain, count in domains.most_common(10):
            print(f"  {domain:50s}: {count:4d} requests")

        # Content Types
        print(f"\n{Colors.OKBLUE}CONTENT TYPES{Colors.ENDC}")
        content_types = self.analyze_content_types()
        for ct, count in content_types.most_common(10):
            print(f"  {ct:50s}: {count:4d}")

        # Slow Requests
        print(f"\n{Colors.WARNING}SLOW REQUESTS (>1000ms){Colors.ENDC}")
        slow = self.find_slow_requests(1000)
        if slow:
            for req in slow[:10]:
                print(f"  {req['time']:8.2f}ms - {req['method']} {req['url'][:70]}")
        else:
            print("  No slow requests found")

        # Errors
        print(f"\n{Colors.FAIL}ERRORS (4xx/5xx){Colors.ENDC}")
        errors = self.find_errors()
        if errors:
            for err in errors[:20]:
                print(f"  {err['status']} {err['status_text']:15s} - {err['method']} {err['url'][:60]}")
        else:
            print(f"  {Colors.OKGREEN}No errors found{Colors.ENDC}")

        # Top Endpoints
        print(f"\n{Colors.OKBLUE}TOP ENDPOINTS{Colors.ENDC}")
        endpoints = self.analyze_endpoints()
        for endpoint, count in endpoints.most_common(15):
            print(f"  {count:4d} - {endpoint}")

        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze HTTP/HTTPS traffic from HAR files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s traffic.har              # Analyze traffic and show report
  %(prog)s captured_traffic.har     # Analyze different HAR file

This tool provides insights into captured HTTP/HTTPS traffic including:
- HTTP method distribution
- Status code analysis
- Response time statistics
- Data transfer metrics
- Top domains and endpoints
- Slow request detection
- Error identification
        """
    )

    parser.add_argument('har_file', help='HAR file to analyze')
    parser.add_argument('--slow-threshold', type=int, default=1000,
                       help='Threshold for slow requests in ms (default: 1000)')
    parser.add_argument('--json', action='store_true',
                       help='Output analysis in JSON format')

    args = parser.parse_args()

    # Create analyzer
    analyzer = TrafficAnalyzer(args.har_file)

    # Load data
    if not analyzer.load():
        sys.exit(1)

    if not analyzer.entries:
        print(f"{Colors.WARNING}No entries found in HAR file{Colors.ENDC}")
        sys.exit(1)

    # Print report
    if args.json:
        # JSON output
        report = {
            'total_entries': len(analyzer.entries),
            'methods': dict(analyzer.analyze_methods()),
            'status_codes': dict(analyzer.analyze_status_codes()),
            'response_times': analyzer.analyze_response_times(),
            'data_transfer': analyzer.analyze_data_transfer(),
            'top_domains': dict(analyzer.analyze_domains().most_common(10)),
            'content_types': dict(analyzer.analyze_content_types().most_common(10)),
            'slow_requests': analyzer.find_slow_requests(args.slow_threshold),
            'errors': analyzer.find_errors()
        }
        print(json.dumps(report, indent=2))
    else:
        # Human-readable report
        analyzer.print_report()


if __name__ == '__main__':
    main()
