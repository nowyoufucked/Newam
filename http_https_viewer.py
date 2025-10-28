#!/usr/bin/env python3
"""
HTTP/HTTPS Traffic Viewer Proxy - Enhanced Version
===================================================
A powerful proxy server for viewing and analyzing HTTP and HTTPS traffic.

WARNING: This tool is for DEFENSIVE SECURITY and DEVELOPMENT purposes only.
Only use this on applications you own or have explicit permission to monitor.
Unauthorized interception of network traffic may be illegal.
"""

import socket
import ssl
import threading
import sys
import argparse
from datetime import datetime
import re
from urllib.parse import urlparse, parse_qs
import select
import json
import time
import gzip
import zlib
from collections import defaultdict
from threading import Lock

# Import decoders module
try:
    from decoders import ContentDecoder, DecoderDisplay
    DECODERS_AVAILABLE = True
except ImportError:
    DECODERS_AVAILABLE = False
    print("Warning: decoders module not found. Advanced decoding features disabled.")


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'


class RequestHistory:
    """Store and manage request history"""

    def __init__(self, max_size=1000):
        self.requests = []
        self.max_size = max_size
        self.lock = Lock()

    def add(self, request_data):
        """Add a request to history"""
        with self.lock:
            if len(self.requests) >= self.max_size:
                self.requests.pop(0)
            self.requests.append(request_data)

    def get_all(self):
        """Get all requests"""
        with self.lock:
            return self.requests.copy()

    def search(self, query):
        """Search requests by URL, method, or body"""
        with self.lock:
            results = []
            for req in self.requests:
                if query.lower() in str(req).lower():
                    results.append(req)
            return results

    def filter_by_domain(self, domain):
        """Filter requests by domain"""
        with self.lock:
            return [req for req in self.requests
                   if domain.lower() in req.get('host', '').lower()]

    def filter_by_method(self, method):
        """Filter requests by HTTP method"""
        with self.lock:
            return [req for req in self.requests
                   if req.get('method', '').upper() == method.upper()]

    def filter_by_status(self, status_code):
        """Filter requests by status code"""
        with self.lock:
            return [req for req in self.requests
                   if req.get('status_code') == status_code]

    def export_to_har(self, filename):
        """Export requests to HAR format"""
        with self.lock:
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {
                        "name": "HTTP/HTTPS Viewer",
                        "version": "2.0"
                    },
                    "entries": []
                }
            }

            for req in self.requests:
                entry = {
                    "startedDateTime": req.get('timestamp', ''),
                    "time": req.get('response_time', 0) * 1000,
                    "request": {
                        "method": req.get('method', ''),
                        "url": f"http://{req.get('host', '')}{req.get('path', '')}",
                        "httpVersion": req.get('version', ''),
                        "headers": [{"name": k, "value": v} for k, v in req.get('headers', {}).items()],
                        "queryString": [],
                        "bodySize": len(req.get('body', b''))
                    },
                    "response": {
                        "status": req.get('status_code', 0),
                        "statusText": req.get('status_text', ''),
                        "httpVersion": req.get('response_version', ''),
                        "headers": [{"name": k, "value": v} for k, v in req.get('response_headers', {}).items()],
                        "bodySize": len(req.get('response_body', b''))
                    },
                    "cache": {},
                    "timings": {
                        "send": 0,
                        "wait": req.get('response_time', 0) * 1000,
                        "receive": 0
                    }
                }
                har["log"]["entries"].append(entry)

            with open(filename, 'w') as f:
                json.dump(har, f, indent=2)


class Statistics:
    """Track proxy statistics"""

    def __init__(self):
        self.lock = Lock()
        self.total_requests = 0
        self.total_responses = 0
        self.total_errors = 0  # Added for GUI compatibility
        self.connections_handled = 0  # Added for GUI compatibility
        self.bytes_sent = 0  # Added for GUI compatibility
        self.bytes_received = 0  # Added for GUI compatibility
        self.requests_by_method = defaultdict(int)
        self.requests_by_domain = defaultdict(int)
        self.status_codes = defaultdict(int)
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.response_times = []
        self.start_time = datetime.now()

    def record_request(self, method, domain, bytes_sent):
        """Record a request"""
        with self.lock:
            self.total_requests += 1
            self.requests_by_method[method.upper()] += 1
            self.requests_by_domain[domain] += 1
            self.total_bytes_sent += bytes_sent
            self.bytes_sent = self.total_bytes_sent  # Sync for GUI

    def record_response(self, status_code, bytes_received, response_time):
        """Record a response"""
        with self.lock:
            self.total_responses += 1
            self.status_codes[status_code] += 1
            self.total_bytes_received += bytes_received
            self.bytes_received = self.total_bytes_received  # Sync for GUI
            if response_time:
                self.response_times.append(response_time)

    def record_error(self):
        """Record an error"""
        with self.lock:
            self.total_errors += 1

    def record_connection(self):
        """Record a connection"""
        with self.lock:
            self.connections_handled += 1

    def get_summary(self):
        """Get statistics summary"""
        with self.lock:
            uptime = datetime.now() - self.start_time
            avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0

            return {
                'uptime': str(uptime),
                'total_requests': self.total_requests,
                'total_responses': self.total_responses,
                'total_bytes_sent': self.total_bytes_sent,
                'total_bytes_received': self.total_bytes_received,
                'requests_by_method': dict(self.requests_by_method),
                'top_domains': dict(sorted(self.requests_by_domain.items(),
                                          key=lambda x: x[1], reverse=True)[:10]),
                'status_codes': dict(self.status_codes),
                'avg_response_time': avg_response_time,
                'min_response_time': min(self.response_times) if self.response_times else 0,
                'max_response_time': max(self.response_times) if self.response_times else 0
            }

    def print_summary(self):
        """Print statistics summary"""
        summary = self.get_summary()
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}PROXY STATISTICS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"Uptime: {summary['uptime']}")
        print(f"Total Requests: {summary['total_requests']}")
        print(f"Total Responses: {summary['total_responses']}")
        print(f"Bytes Sent: {summary['total_bytes_sent']:,} ({summary['total_bytes_sent']/1024:.2f} KB)")
        print(f"Bytes Received: {summary['total_bytes_received']:,} ({summary['total_bytes_received']/1024:.2f} KB)")

        if summary['avg_response_time'] > 0:
            print(f"\n{Colors.OKCYAN}Response Times:{Colors.ENDC}")
            print(f"  Average: {summary['avg_response_time']*1000:.2f} ms")
            print(f"  Min: {summary['min_response_time']*1000:.2f} ms")
            print(f"  Max: {summary['max_response_time']*1000:.2f} ms")

        if summary['requests_by_method']:
            print(f"\n{Colors.OKCYAN}Requests by Method:{Colors.ENDC}")
            for method, count in sorted(summary['requests_by_method'].items()):
                print(f"  {method}: {count}")

        if summary['status_codes']:
            print(f"\n{Colors.OKCYAN}Status Codes:{Colors.ENDC}")
            for code, count in sorted(summary['status_codes'].items()):
                print(f"  {code}: {count}")

        if summary['top_domains']:
            print(f"\n{Colors.OKCYAN}Top Domains:{Colors.ENDC}")
            for domain, count in list(summary['top_domains'].items())[:5]:
                print(f"  {domain}: {count} requests")

        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")


class HTTPSViewer:
    """Enhanced HTTP/HTTPS proxy server for viewing traffic"""

    def __init__(self, host='127.0.0.1', port=8888, verbose=False, save_to_file=None,
                 filter_domain=None, filter_method=None, filter_status=None,
                 show_body=False, pretty_json=True, max_body_size=10000,
                 decode_content=True):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.save_to_file = save_to_file
        self.connection_count = 0
        self.show_body = show_body
        self.pretty_json = pretty_json
        self.max_body_size = max_body_size
        self.decode_content = decode_content and DECODERS_AVAILABLE

        # Filters
        self.filter_domain = filter_domain
        self.filter_method = filter_method.upper() if filter_method else None
        self.filter_status = filter_status

        # History and statistics
        self.history = RequestHistory()
        self.stats = Statistics()

        if save_to_file:
            self.log_file = open(save_to_file, 'a', encoding='utf-8')
        else:
            self.log_file = None

    def log(self, message, color=None):
        """Log a message to console and optionally to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_msg = f"[{timestamp}] {message}"

        if color:
            print(f"{color}{log_msg}{Colors.ENDC}")
        else:
            print(log_msg)

        if self.log_file:
            self.log_file.write(log_msg + '\n')
            self.log_file.flush()

    def should_filter(self, method=None, domain=None, status_code=None):
        """Check if request/response should be filtered out"""
        if self.filter_method and method and method.upper() != self.filter_method:
            return True
        if self.filter_domain and domain and self.filter_domain.lower() not in domain.lower():
            return True
        if self.filter_status and status_code and status_code != self.filter_status:
            return True
        return False

    def decode_content(self, data, encoding):
        """Decode content based on encoding"""
        try:
            if encoding == 'gzip':
                return gzip.decompress(data)
            elif encoding == 'deflate':
                return zlib.decompress(data)
            elif encoding == 'br':
                try:
                    import brotli
                    return brotli.decompress(data)
                except ImportError:
                    return data
            else:
                return data
        except:
            return data

    def format_json(self, data):
        """Pretty print JSON data"""
        try:
            json_obj = json.loads(data)
            return json.dumps(json_obj, indent=2, ensure_ascii=False)
        except:
            return data

    def parse_http_request(self, data):
        """Parse HTTP request and extract useful information"""
        try:
            # Find headers/body separator
            separator_idx = data.find(b'\r\n\r\n')
            if separator_idx == -1:
                headers_data = data
                body = b''
            else:
                headers_data = data[:separator_idx]
                body = data[separator_idx + 4:]

            lines = headers_data.split(b'\r\n')
            if not lines:
                return None

            # Parse request line
            request_line = lines[0].decode('utf-8', errors='replace')
            parts = request_line.split(' ')
            if len(parts) >= 3:
                method, path, version = parts[0], parts[1], parts[2]
            else:
                return None

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if not line:
                    break
                try:
                    header_line = line.decode('utf-8', errors='replace')
                    if ':' in header_line:
                        key, value = header_line.split(':', 1)
                        headers[key.strip()] = value.strip()
                except:
                    pass

            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body,
                'raw': data
            }
        except Exception as e:
            self.log(f"Error parsing request: {e}", Colors.FAIL)
            return None

    def parse_http_response(self, data):
        """Parse HTTP response"""
        try:
            separator_idx = data.find(b'\r\n\r\n')
            if separator_idx == -1:
                headers_data = data
                body = b''
            else:
                headers_data = data[:separator_idx]
                body = data[separator_idx + 4:]

            lines = headers_data.split(b'\r\n')
            if not lines:
                return None

            # Parse status line
            status_line = lines[0].decode('utf-8', errors='replace')
            parts = status_line.split(' ', 2)
            if len(parts) >= 2:
                version = parts[0]
                status_code = int(parts[1])
                status_text = parts[2] if len(parts) > 2 else ''
            else:
                return None

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if not line:
                    break
                try:
                    header_line = line.decode('utf-8', errors='replace')
                    if ':' in header_line:
                        key, value = header_line.split(':', 1)
                        headers[key.strip()] = value.strip()
                except:
                    pass

            return {
                'version': version,
                'status_code': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': body,
                'raw': data
            }
        except:
            return None

    def decode_and_display_headers(self, headers):
        """Decode and display special headers like Auth, Cookies, etc."""
        if not self.decode_content or not DECODERS_AVAILABLE:
            return

        # Decode Authorization header
        if 'Authorization' in headers:
            auth = headers['Authorization']
            # Check for Basic Auth
            if auth.startswith('Basic '):
                decoded = ContentDecoder.decode_base64(auth[6:])
                if decoded:
                    self.log(f"  {Colors.WARNING}[Decoded Auth]:{Colors.ENDC} {decoded.decode('utf-8', errors='replace')}")
            # Check for Bearer (JWT)
            elif auth.startswith('Bearer '):
                jwt_data = ContentDecoder.decode_jwt(auth)
                if jwt_data:
                    self.log(f"  {Colors.WARNING}[JWT Decoded]:{Colors.ENDC}")
                    self.log(f"    Header: {json.dumps(jwt_data['header'], indent=6)}", Colors.GRAY)
                    self.log(f"    Payload: {json.dumps(jwt_data['payload'], indent=6)}", Colors.GRAY)

        # Decode Cookie header
        if 'Cookie' in headers:
            cookies = ContentDecoder.parse_cookies(headers['Cookie'])
            if cookies and len(cookies) > 1:  # Only show if multiple cookies or complex
                self.log(f"  {Colors.WARNING}[Parsed Cookies]:{Colors.ENDC}")
                for name, value in list(cookies.items())[:5]:  # Show first 5
                    display_value = value if len(value) < 40 else value[:40] + '...'
                    self.log(f"    {name}: {display_value}", Colors.GRAY)

        # Decode Set-Cookie header
        if 'Set-Cookie' in headers:
            cookie_data = ContentDecoder.parse_set_cookie(headers['Set-Cookie'])
            if cookie_data:
                self.log(f"  {Colors.WARNING}[Parsed Set-Cookie]:{Colors.ENDC}")
                for key, value in cookie_data.items():
                    if key not in ['name', 'value']:
                        self.log(f"    {key}: {value}", Colors.GRAY)

    def display_body(self, body, headers, label="Body"):
        """Display request/response body with formatting and decoding"""
        if not body or len(body) == 0:
            return

        if len(body) > self.max_body_size:
            self.log(f"{label}: {len(body)} bytes (truncated, showing first {self.max_body_size} bytes)",
                    Colors.GRAY)
            body = body[:self.max_body_size]
        else:
            self.log(f"{label}: {len(body)} bytes", Colors.GRAY)

        # Try to decode if compressed
        content_encoding = headers.get('Content-Encoding', '').lower()
        if content_encoding:
            body = self.decode_content(body, content_encoding)

        # Check content type
        content_type = headers.get('Content-Type', '').lower()

        # Handle form data with decoder
        if self.decode_content and DECODERS_AVAILABLE:
            # Parse form data
            if 'application/x-www-form-urlencoded' in content_type:
                form_data = ContentDecoder.parse_form_data(body, content_type)
                if form_data:
                    self.log(f"{Colors.WARNING}[Decoded Form Data]:{Colors.ENDC}")
                    for key, value in form_data.items():
                        self.log(f"  {key}: {value}", Colors.GRAY)
                    return

            # Parse multipart data
            if 'multipart/form-data' in content_type:
                boundary_match = re.search(r'boundary=([^;]+)', content_type)
                if boundary_match:
                    boundary = boundary_match.group(1).strip('"')
                    parts = ContentDecoder.parse_multipart(body, boundary)
                    if parts:
                        self.log(f"{Colors.WARNING}[Decoded Multipart Data]:{Colors.ENDC}")
                        for i, part in enumerate(parts, 1):
                            self.log(f"  Part {i}:", Colors.GRAY)
                            if part['name']:
                                self.log(f"    Name: {part['name']}", Colors.GRAY)
                            if part['filename']:
                                self.log(f"    Filename: {part['filename']}", Colors.GRAY)
                            self.log(f"    Size: {len(part['body'])} bytes", Colors.GRAY)
                        return

            # Pretty print HTML
            if 'text/html' in content_type:
                pretty_html = ContentDecoder.pretty_print_html(body)
                if pretty_html:
                    self.log(f"{Colors.WARNING}[Formatted HTML]:{Colors.ENDC}")
                    self.log(pretty_html[:1500], Colors.GRAY)
                    if len(pretty_html) > 1500:
                        self.log("... (truncated)", Colors.GRAY)
                    return

            # Pretty print XML
            if 'xml' in content_type or 'text/xml' in content_type or 'application/xml' in content_type:
                pretty_xml = ContentDecoder.pretty_print_xml(body)
                if pretty_xml:
                    self.log(f"{Colors.WARNING}[Formatted XML]:{Colors.ENDC}")
                    self.log(pretty_xml[:1500], Colors.GRAY)
                    if len(pretty_xml) > 1500:
                        self.log("... (truncated)", Colors.GRAY)
                    return

        # Try to display as text
        try:
            body_text = body.decode('utf-8', errors='replace')

            # Pretty print JSON
            if self.pretty_json and ('application/json' in content_type or
                                     body_text.strip().startswith(('{', '['))):
                try:
                    formatted = self.format_json(body_text)
                    self.log(formatted, Colors.GRAY)
                    return
                except:
                    pass

            # Display as text
            if len(body_text) < 1000:
                self.log(body_text, Colors.GRAY)
            else:
                self.log(body_text[:1000] + "\n... (truncated)", Colors.GRAY)
        except:
            # Binary content - show hex dump if decoders available
            if self.decode_content and DECODERS_AVAILABLE:
                hex_dump = ContentDecoder.hex_dump(body, length=256)
                if hex_dump:
                    self.log(f"{Colors.WARNING}[Hex Dump]:{Colors.ENDC}")
                    self.log(hex_dump, Colors.GRAY)
            else:
                self.log(f"<Binary content: {len(body)} bytes>", Colors.GRAY)

    def display_request(self, request_info, is_https=False):
        """Display HTTP request in a formatted way"""
        protocol = "HTTPS" if is_https else "HTTP"

        # Check filters
        host = request_info['headers'].get('Host', '')
        if self.should_filter(method=request_info['method'], domain=host):
            return False

        self.log("=" * 80, Colors.BOLD)
        self.log(f"{protocol} REQUEST", Colors.HEADER)
        self.log("-" * 80)
        self.log(f"{request_info['method']} {request_info['path']} {request_info['version']}",
                Colors.OKBLUE)

        if self.verbose:
            self.log("Headers:", Colors.OKCYAN)
            for key, value in request_info['headers'].items():
                self.log(f"  {key}: {value}")
        else:
            # Show important headers
            important_headers = ['Host', 'User-Agent', 'Content-Type', 'Content-Length',
                               'Authorization', 'Cookie']
            for key in important_headers:
                if key in request_info['headers']:
                    value = request_info['headers'][key]
                    # Truncate long headers
                    if len(value) > 100 and key in ['Authorization', 'Cookie']:
                        value = value[:100] + "... (truncated)"
                    self.log(f"  {key}: {value}")

        # Decode special headers
        self.decode_and_display_headers(request_info['headers'])

        # Display body if requested
        if self.show_body and request_info.get('body'):
            self.log("-" * 80)
            self.display_body(request_info['body'], request_info['headers'], "Request Body")

        return True

    def display_response(self, response_info, is_https=False, response_time=None):
        """Display HTTP response in a formatted way"""
        protocol = "HTTPS" if is_https else "HTTP"

        # Check status filter
        if self.should_filter(status_code=response_info.get('status_code')):
            return False

        try:
            status_code = response_info['status_code']
            status_text = response_info['status_text']

            # Color code based on status
            if status_code < 300:
                status_color = Colors.OKGREEN
            elif status_code < 400:
                status_color = Colors.OKCYAN
            elif status_code < 500:
                status_color = Colors.WARNING
            else:
                status_color = Colors.FAIL

            time_str = f" ({response_time*1000:.2f}ms)" if response_time else ""
            self.log(f"{protocol} RESPONSE: {response_info['version']} {status_code} {status_text}{time_str}",
                    status_color)

            if self.verbose:
                self.log("Response Headers:", Colors.OKCYAN)
                for key, value in response_info.get('headers', {}).items():
                    self.log(f"  {key}: {value}")
            else:
                # Show important response headers
                important_headers = ['Content-Type', 'Content-Length', 'Content-Encoding',
                                   'Set-Cookie', 'Location', 'Cache-Control']
                for key in important_headers:
                    if key in response_info.get('headers', {}):
                        value = response_info['headers'][key]
                        if len(value) > 100:
                            value = value[:100] + "... (truncated)"
                        self.log(f"  {key}: {value}")

            # Decode special response headers
            self.decode_and_display_headers(response_info.get('headers', {}))

            # Display body if requested
            if self.show_body and response_info.get('body'):
                self.log("-" * 80)
                self.display_body(response_info['body'], response_info['headers'], "Response Body")

        except Exception as e:
            self.log(f"Error displaying response: {e}", Colors.FAIL)

        self.log("=" * 80, Colors.BOLD)
        return True

    def handle_client(self, client_socket, client_address):
        """Handle client connection"""
        self.connection_count += 1
        conn_id = self.connection_count
        start_time = time.time()

        try:
            # Receive initial request
            client_socket.settimeout(5)
            initial_data = client_socket.recv(8192)

            if not initial_data:
                return

            # Check if it's a CONNECT request (HTTPS)
            if initial_data.startswith(b'CONNECT '):
                # Parse CONNECT request
                lines = initial_data.split(b'\r\n')
                request_line = lines[0].decode('utf-8', errors='replace')
                parts = request_line.split(' ')

                if len(parts) >= 2:
                    host_port = parts[1]
                    if ':' in host_port:
                        target_host, target_port = host_port.rsplit(':', 1)
                        target_port = int(target_port)
                    else:
                        target_host = host_port
                        target_port = 443

                    if not self.should_filter(domain=target_host):
                        self.log(f"[Connection #{conn_id}] HTTPS CONNECT to {target_host}:{target_port}",
                               Colors.WARNING)

                    self.stats.record_request('CONNECT', target_host, len(initial_data))
                    self.handle_https_connect(client_socket, client_address, target_host, target_port)
            else:
                # Regular HTTP request
                request_info = self.parse_http_request(initial_data)
                if request_info:
                    host = request_info['headers'].get('Host', '')

                    # Display request
                    displayed = self.display_request(request_info, is_https=False)

                    if not displayed:
                        # Filtered out, but still forward
                        pass

                    # Record statistics
                    self.stats.record_request(request_info['method'], host, len(initial_data))

                    # Extract target host
                    if ':' in host:
                        target_host, target_port = host.split(':')
                        target_port = int(target_port)
                    else:
                        target_host = host
                        target_port = 80

                    # Connect to target server
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_socket.settimeout(10)

                    try:
                        server_socket.connect((target_host, target_port))
                        server_socket.sendall(initial_data)

                        # Receive and forward response
                        response = b''
                        while True:
                            chunk = server_socket.recv(8192)
                            if not chunk:
                                break
                            response += chunk
                            client_socket.sendall(chunk)

                        response_time = time.time() - start_time

                        # Parse and display response
                        if response:
                            response_info = self.parse_http_response(response)
                            if response_info and displayed:
                                self.display_response(response_info, is_https=False,
                                                    response_time=response_time)

                            # Record statistics
                            if response_info:
                                self.stats.record_response(response_info['status_code'],
                                                          len(response), response_time)

                                # Add to history
                                self.history.add({
                                    'timestamp': datetime.now().isoformat(),
                                    'method': request_info['method'],
                                    'path': request_info['path'],
                                    'version': request_info['version'],
                                    'host': host,
                                    'headers': request_info['headers'],
                                    'body': request_info.get('body', b''),
                                    'status_code': response_info['status_code'],
                                    'status_text': response_info['status_text'],
                                    'response_version': response_info['version'],
                                    'response_headers': response_info['headers'],
                                    'response_body': response_info.get('body', b''),
                                    'response_time': response_time
                                })

                    except Exception as e:
                        self.log(f"Error forwarding HTTP request: {e}", Colors.FAIL)
                    finally:
                        server_socket.close()

        except Exception as e:
            self.log(f"[Connection #{conn_id}] Error: {e}", Colors.FAIL)
        finally:
            client_socket.close()

    def handle_https_connect(self, client_socket, client_address, target_host, target_port):
        """Handle HTTPS CONNECT request"""
        try:
            # Send connection established response
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            # Connect to target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)

            try:
                server_socket.connect((target_host, target_port))

                if not self.should_filter(domain=target_host):
                    self.log(f"HTTPS tunnel established to {target_host}:{target_port}", Colors.OKGREEN)

                # Relay data between client and server
                client_socket.setblocking(False)
                server_socket.setblocking(False)

                bytes_sent = 0
                bytes_received = 0

                while True:
                    readable, _, exceptional = select.select(
                        [client_socket, server_socket], [],
                        [client_socket, server_socket], 1.0
                    )

                    if exceptional:
                        break

                    for sock in readable:
                        try:
                            data = sock.recv(8192)
                            if not data:
                                self.stats.record_response(0, bytes_received, None)
                                return

                            if sock is client_socket:
                                # Data from client to server
                                server_socket.sendall(data)
                                bytes_sent += len(data)
                                if self.verbose and not self.should_filter(domain=target_host):
                                    self.log(f"Client -> Server: {len(data)} bytes", Colors.OKCYAN)
                            else:
                                # Data from server to client
                                client_socket.sendall(data)
                                bytes_received += len(data)
                                if self.verbose and not self.should_filter(domain=target_host):
                                    self.log(f"Server -> Client: {len(data)} bytes", Colors.OKGREEN)
                        except:
                            self.stats.record_response(0, bytes_received, None)
                            return

            except Exception as e:
                self.log(f"Error in HTTPS tunnel: {e}", Colors.FAIL)
            finally:
                server_socket.close()

        except Exception as e:
            self.log(f"Error handling CONNECT: {e}", Colors.FAIL)
        finally:
            client_socket.close()

    def start(self):
        """Start the proxy server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)

            self.log("=" * 80, Colors.BOLD)
            self.log(f"HTTP/HTTPS Viewer Proxy Started - Enhanced Mode", Colors.HEADER)
            self.log(f"Listening on {self.host}:{self.port}", Colors.OKGREEN)

            if self.filter_domain:
                self.log(f"Filter: Domain contains '{self.filter_domain}'", Colors.WARNING)
            if self.filter_method:
                self.log(f"Filter: Method = {self.filter_method}", Colors.WARNING)
            if self.filter_status:
                self.log(f"Filter: Status code = {self.filter_status}", Colors.WARNING)
            if self.show_body:
                self.log(f"Body display: ENABLED (max {self.max_body_size} bytes)", Colors.WARNING)

            self.log(f"Configure your application to use this proxy", Colors.WARNING)
            self.log(f"Press Ctrl+C to stop and show statistics", Colors.WARNING)
            self.log("=" * 80, Colors.BOLD)

            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            self.log("\n\nShutting down proxy server...", Colors.WARNING)
            self.stats.print_summary()

            # Ask if user wants to export data
            try:
                export = input(f"\n{Colors.OKCYAN}Export history to HAR file? (y/n): {Colors.ENDC}")
                if export.lower() == 'y':
                    filename = input(f"{Colors.OKCYAN}Enter filename (default: traffic.har): {Colors.ENDC}").strip()
                    if not filename:
                        filename = "traffic.har"
                    self.history.export_to_har(filename)
                    print(f"{Colors.OKGREEN}Exported to {filename}{Colors.ENDC}")
            except:
                pass

        except Exception as e:
            self.log(f"Server error: {e}", Colors.FAIL)
        finally:
            server_socket.close()
            if self.log_file:
                self.log_file.close()


def main():
    parser = argparse.ArgumentParser(
        description='HTTP/HTTPS Traffic Viewer Proxy - Enhanced Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start proxy on 127.0.0.1:8888
  %(prog)s -p 9000                  # Use port 9000
  %(prog)s -v                       # Verbose mode (show all headers)
  %(prog)s -b                       # Show request/response bodies
  %(prog)s -o traffic.log           # Save traffic to file
  %(prog)s --filter-domain api.example.com    # Only show traffic for this domain
  %(prog)s --filter-method POST     # Only show POST requests
  %(prog)s --filter-status 404      # Only show 404 responses
  %(prog)s -v -b --pretty-json      # Full verbose with pretty JSON

WARNING: This tool is for defensive security and development purposes only.
Only use on applications you own or have explicit permission to monitor.
        """
    )

    parser.add_argument('-H', '--host', default='127.0.0.1',
                       help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=8888,
                       help='Port to listen on (default: 8888)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose mode (show all headers and details)')
    parser.add_argument('-b', '--show-body', action='store_true',
                       help='Show request/response bodies')
    parser.add_argument('-o', '--output', help='Save traffic to file')
    parser.add_argument('--filter-domain', help='Filter by domain (show only matching)')
    parser.add_argument('--filter-method', help='Filter by HTTP method (GET, POST, etc.)')
    parser.add_argument('--filter-status', type=int, help='Filter by status code')
    parser.add_argument('--pretty-json', action='store_true', default=True,
                       help='Pretty print JSON bodies (default: True)')
    parser.add_argument('--max-body-size', type=int, default=10000,
                       help='Maximum body size to display in bytes (default: 10000)')
    parser.add_argument('--decode', action='store_true', default=True,
                       help='Auto-decode content (JWT, Base64, cookies, form data, etc.) (default: True)')
    parser.add_argument('--no-decode', action='store_false', dest='decode',
                       help='Disable auto-decoding')

    args = parser.parse_args()

    proxy = HTTPSViewer(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        save_to_file=args.output,
        filter_domain=args.filter_domain,
        filter_method=args.filter_method,
        filter_status=args.filter_status,
        show_body=args.show_body,
        pretty_json=args.pretty_json,
        max_body_size=args.max_body_size,
        decode_content=args.decode
    )

    try:
        proxy.start()
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
