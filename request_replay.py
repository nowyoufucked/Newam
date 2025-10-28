#!/usr/bin/env python3
"""
Request Replay Utility
======================
Load and replay HTTP requests from HAR files or saved sessions.

WARNING: This tool is for DEFENSIVE SECURITY and DEVELOPMENT purposes only.
Only replay requests to applications you own or have explicit permission to test.
"""

import json
import sys
import argparse
import requests
from datetime import datetime
import time


class Colors:
    """ANSI color codes"""
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    OKCYAN = '\033[96m'
    BOLD = '\033[1m'


class RequestReplay:
    """Replay HTTP requests from saved data"""

    def __init__(self, delay=0, verbose=False):
        self.delay = delay
        self.verbose = verbose
        self.session = requests.Session()

    def load_har(self, filename):
        """Load requests from HAR file"""
        try:
            with open(filename, 'r') as f:
                har_data = json.load(f)

            requests_list = []
            for entry in har_data.get('log', {}).get('entries', []):
                req = entry.get('request', {})
                requests_list.append({
                    'method': req.get('method'),
                    'url': req.get('url'),
                    'headers': {h['name']: h['value'] for h in req.get('headers', [])},
                    'body': req.get('postData', {}).get('text', '')
                })

            return requests_list
        except Exception as e:
            print(f"{Colors.FAIL}Error loading HAR file: {e}{Colors.ENDC}")
            return []

    def replay_request(self, request_data, modify_host=None):
        """Replay a single request"""
        try:
            method = request_data['method']
            url = request_data['url']
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')

            # Modify host if specified
            if modify_host:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(url)
                url = urlunparse((
                    parsed.scheme,
                    modify_host,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))

            # Remove problematic headers
            headers_to_remove = ['Host', 'Content-Length', 'Connection']
            for header in headers_to_remove:
                headers.pop(header, None)

            print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Replaying: {method} {url}{Colors.ENDC}")

            start_time = time.time()

            # Make request
            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=headers, data=body, timeout=10)
            elif method.upper() == 'PUT':
                response = self.session.put(url, headers=headers, data=body, timeout=10)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=10)
            elif method.upper() == 'PATCH':
                response = self.session.patch(url, headers=headers, data=body, timeout=10)
            else:
                response = self.session.request(method, url, headers=headers, data=body, timeout=10)

            elapsed = time.time() - start_time

            # Print response
            if response.status_code < 300:
                color = Colors.OKGREEN
            elif response.status_code < 400:
                color = Colors.OKCYAN
            else:
                color = Colors.FAIL

            print(f"{color}Response: {response.status_code} {response.reason} ({elapsed*1000:.2f}ms){Colors.ENDC}")

            if self.verbose:
                print(f"\nResponse Headers:")
                for key, value in response.headers.items():
                    print(f"  {key}: {value}")

                print(f"\nResponse Body ({len(response.content)} bytes):")
                try:
                    # Try to pretty print JSON
                    json_data = response.json()
                    print(json.dumps(json_data, indent=2)[:1000])
                except:
                    # Not JSON or error
                    print(response.text[:1000])

            print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}")

            return response

        except Exception as e:
            print(f"{Colors.FAIL}Error replaying request: {e}{Colors.ENDC}")
            return None

    def replay_all(self, requests_list, modify_host=None, filter_method=None, limit=None):
        """Replay all requests"""
        successful = 0
        failed = 0
        count = 0

        print(f"\n{Colors.BOLD}Starting replay of {len(requests_list)} requests{Colors.ENDC}\n")

        for req in requests_list:
            # Apply filters
            if filter_method and req['method'].upper() != filter_method.upper():
                continue

            if limit and count >= limit:
                break

            # Replay request
            response = self.replay_request(req, modify_host=modify_host)

            if response and response.status_code < 400:
                successful += 1
            else:
                failed += 1

            count += 1

            # Delay between requests
            if self.delay > 0 and count < len(requests_list):
                time.sleep(self.delay)

        # Summary
        print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}REPLAY SUMMARY{Colors.ENDC}")
        print(f"Total replayed: {count}")
        print(f"{Colors.OKGREEN}Successful: {successful}{Colors.ENDC}")
        print(f"{Colors.FAIL}Failed: {failed}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")


def main():
    parser = argparse.ArgumentParser(
        description='HTTP Request Replay Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s traffic.har                    # Replay all requests from HAR file
  %(prog)s traffic.har -v                 # Verbose mode
  %(prog)s traffic.har --delay 1          # 1 second delay between requests
  %(prog)s traffic.har --modify-host localhost:8080  # Change target host
  %(prog)s traffic.har --filter-method POST  # Only replay POST requests
  %(prog)s traffic.har --limit 10         # Only replay first 10 requests

WARNING: This tool is for defensive security and development purposes only.
Only replay requests to systems you own or have explicit permission to test.
        """
    )

    parser.add_argument('har_file', help='HAR file to load requests from')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose mode (show full responses)')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--modify-host', help='Change target host (e.g., localhost:8080)')
    parser.add_argument('--filter-method', help='Only replay requests with this method')
    parser.add_argument('--limit', type=int, help='Maximum number of requests to replay')

    args = parser.parse_args()

    # Create replayer
    replayer = RequestReplay(delay=args.delay, verbose=args.verbose)

    # Load requests
    print(f"{Colors.OKCYAN}Loading requests from {args.har_file}...{Colors.ENDC}")
    requests_list = replayer.load_har(args.har_file)

    if not requests_list:
        print(f"{Colors.FAIL}No requests found or error loading file{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.OKGREEN}Loaded {len(requests_list)} requests{Colors.ENDC}")

    # Replay requests
    replayer.replay_all(
        requests_list,
        modify_host=args.modify_host,
        filter_method=args.filter_method,
        limit=args.limit
    )


if __name__ == '__main__':
    main()
