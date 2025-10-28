#!/usr/bin/env python3
"""
HTTP/HTTPS Traffic Viewer Proxy
=================================
A proxy server for viewing HTTP and HTTPS traffic from targeted applications.

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
from urllib.parse import urlparse
import select


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


class HTTPSViewer:
    """HTTP/HTTPS proxy server for viewing traffic"""

    def __init__(self, host='127.0.0.1', port=8888, verbose=False, save_to_file=None):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.save_to_file = save_to_file
        self.connection_count = 0

        if save_to_file:
            self.log_file = open(save_to_file, 'a', encoding='utf-8')
        else:
            self.log_file = None

    def log(self, message, color=None):
        """Log a message to console and optionally to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}"

        if color:
            print(f"{color}{log_msg}{Colors.ENDC}")
        else:
            print(log_msg)

        if self.log_file:
            self.log_file.write(log_msg + '\n')
            self.log_file.flush()

    def parse_http_request(self, data):
        """Parse HTTP request and extract useful information"""
        try:
            lines = data.split(b'\r\n')
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
                'raw': data
            }
        except Exception as e:
            self.log(f"Error parsing request: {e}", Colors.FAIL)
            return None

    def display_request(self, request_info, is_https=False):
        """Display HTTP request in a formatted way"""
        protocol = "HTTPS" if is_https else "HTTP"

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
            important_headers = ['Host', 'User-Agent', 'Content-Type', 'Content-Length']
            for key in important_headers:
                if key in request_info['headers']:
                    self.log(f"  {key}: {request_info['headers'][key]}")

    def display_response(self, response_data, is_https=False):
        """Display HTTP response in a formatted way"""
        protocol = "HTTPS" if is_https else "HTTP"

        try:
            lines = response_data.split(b'\r\n', 1)
            if lines:
                status_line = lines[0].decode('utf-8', errors='replace')
                self.log(f"{protocol} RESPONSE: {status_line}", Colors.OKGREEN)

                if self.verbose and len(lines) > 1:
                    headers_end = response_data.find(b'\r\n\r\n')
                    if headers_end > 0:
                        headers = response_data[:headers_end].decode('utf-8', errors='replace')
                        self.log("Response Headers:", Colors.OKCYAN)
                        for line in headers.split('\r\n')[1:]:
                            if line:
                                self.log(f"  {line}")
        except Exception as e:
            self.log(f"Error displaying response: {e}", Colors.FAIL)

        self.log("=" * 80, Colors.BOLD)

    def handle_http_request(self, client_socket, client_address):
        """Handle HTTP request (non-CONNECT)"""
        try:
            # Receive request from client
            request = b''
            client_socket.settimeout(5)

            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                    if b'\r\n\r\n' in request:
                        break
                except socket.timeout:
                    break

            if not request:
                return

            # Parse and display request
            request_info = self.parse_http_request(request)
            if request_info:
                self.display_request(request_info, is_https=False)

                # Extract target host and port
                host = request_info['headers'].get('Host', '')
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

                    # Forward request
                    server_socket.sendall(request)

                    # Receive response
                    response = b''
                    while True:
                        chunk = server_socket.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        client_socket.sendall(chunk)

                    # Display response
                    if response:
                        self.display_response(response, is_https=False)

                except Exception as e:
                    self.log(f"Error connecting to target: {e}", Colors.FAIL)
                finally:
                    server_socket.close()

        except Exception as e:
            self.log(f"Error handling HTTP request: {e}", Colors.FAIL)
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

                self.log(f"HTTPS tunnel established to {target_host}:{target_port}", Colors.OKGREEN)

                # Relay data between client and server
                client_socket.setblocking(False)
                server_socket.setblocking(False)

                while True:
                    readable, _, exceptional = select.select(
                        [client_socket, server_socket], [],
                        [client_socket, server_socket], 1.0
                    )

                    if exceptional:
                        break

                    for sock in readable:
                        try:
                            data = sock.recv(4096)
                            if not data:
                                return

                            if sock is client_socket:
                                # Data from client to server
                                server_socket.sendall(data)
                                if self.verbose:
                                    self.log(f"Client -> Server: {len(data)} bytes", Colors.OKCYAN)
                            else:
                                # Data from server to client
                                client_socket.sendall(data)
                                if self.verbose:
                                    self.log(f"Server -> Client: {len(data)} bytes", Colors.OKGREEN)
                        except:
                            return

            except Exception as e:
                self.log(f"Error in HTTPS tunnel: {e}", Colors.FAIL)
            finally:
                server_socket.close()

        except Exception as e:
            self.log(f"Error handling CONNECT: {e}", Colors.FAIL)
        finally:
            client_socket.close()

    def handle_client(self, client_socket, client_address):
        """Handle client connection"""
        self.connection_count += 1
        conn_id = self.connection_count

        try:
            # Receive initial request
            client_socket.settimeout(5)
            initial_data = client_socket.recv(4096)

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

                    self.log(f"[Connection #{conn_id}] HTTPS CONNECT to {target_host}:{target_port}",
                           Colors.WARNING)
                    self.handle_https_connect(client_socket, client_address, target_host, target_port)
            else:
                # Regular HTTP request
                self.log(f"[Connection #{conn_id}] HTTP request from {client_address[0]}:{client_address[1]}",
                       Colors.WARNING)
                # Put the data back for processing
                request_info = self.parse_http_request(initial_data)
                if request_info:
                    self.display_request(request_info, is_https=False)

                    # Extract target host
                    host = request_info['headers'].get('Host', '')
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
                            chunk = server_socket.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            client_socket.sendall(chunk)

                        if response:
                            self.display_response(response, is_https=False)

                    except Exception as e:
                        self.log(f"Error forwarding HTTP request: {e}", Colors.FAIL)
                    finally:
                        server_socket.close()

        except Exception as e:
            self.log(f"[Connection #{conn_id}] Error: {e}", Colors.FAIL)
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
            self.log(f"HTTP/HTTPS Viewer Proxy Started", Colors.HEADER)
            self.log(f"Listening on {self.host}:{self.port}", Colors.OKGREEN)
            self.log(f"Configure your application to use this proxy", Colors.WARNING)
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
            self.log("\nShutting down proxy server...", Colors.WARNING)
        except Exception as e:
            self.log(f"Server error: {e}", Colors.FAIL)
        finally:
            server_socket.close()
            if self.log_file:
                self.log_file.close()


def main():
    parser = argparse.ArgumentParser(
        description='HTTP/HTTPS Traffic Viewer Proxy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start proxy on 127.0.0.1:8888
  %(prog)s -p 9000                  # Use port 9000
  %(prog)s -v                       # Verbose mode (show all headers)
  %(prog)s -o traffic.log           # Save traffic to file

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
    parser.add_argument('-o', '--output', help='Save traffic to file')

    args = parser.parse_args()

    proxy = HTTPSViewer(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        save_to_file=args.output
    )

    try:
        proxy.start()
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
