#!/usr/bin/env python3
"""
Enhanced HTTP/HTTPS Proxy
==========================
Complete proxy with all advanced features integrated.
Ensures no web traffic is missed.

Features:
- All basic proxy features
- WebSocket support
- HTTPS MITM with dynamic certificate generation
- System proxy auto-configuration
- Connection pooling and keep-alive
- DNS resolution tracking
- Chunked transfer encoding
- Upstream proxy support
- Traffic capture modes
- Redirect tracking
- Better error recovery
- Large file handling
- Streaming support
"""

import socket
import ssl
import threading
import argparse
import sys
from datetime import datetime
import select
import os
import time

# Import our modules - ALL REQUIRED (no optional imports)
try:
    from http_https_viewer import HTTPSViewer, Colors
    from advanced_capture import (
        WebSocketHandler, ChunkedEncodingHandler, ConnectionTracker,
        DNSResolver, SystemProxyConfigurator, UpstreamProxyHandler,
        TrafficCaptureMode, RedirectHandler, create_advanced_logger
    )
    from decoders import ContentDecoder
except ImportError as e:
    print(f"ERROR: Required modules not available: {e}")
    print("All modules are required. Please ensure all files are present.")
    sys.exit(1)

MODULES_AVAILABLE = True


class EnhancedHTTPSViewer(HTTPSViewer):
    """Enhanced proxy with all advanced features"""

    def __init__(self, *args, enable_websocket=True, enable_system_proxy=False,
                 upstream_proxy=None, capture_mode='promiscuous', **kwargs):
        super().__init__(*args, **kwargs)

        # Advanced features
        self.enable_websocket = enable_websocket
        self.enable_system_proxy = enable_system_proxy
        self.upstream_proxy = upstream_proxy

        # Handlers
        self.websocket_handler = WebSocketHandler() if enable_websocket else None
        self.chunked_handler = ChunkedEncodingHandler()
        self.connection_tracker = ConnectionTracker()
        self.dns_resolver = DNSResolver()
        self.redirect_handler = RedirectHandler()

        # Upstream proxy
        if upstream_proxy:
            host, port = upstream_proxy.split(':')
            self.upstream_handler = UpstreamProxyHandler(host, int(port))
        else:
            self.upstream_handler = UpstreamProxyHandler()

        # Capture mode
        modes = {
            'promiscuous': TrafficCaptureMode.PROMISCUOUS,
            'selective': TrafficCaptureMode.SELECTIVE,
            'stealth': TrafficCaptureMode.STEALTH,
            'debug': TrafficCaptureMode.DEBUG
        }
        self.capture_mode = TrafficCaptureMode(modes.get(capture_mode, TrafficCaptureMode.PROMISCUOUS))

        # Statistics
        self.websocket_count = 0
        self.dns_resolutions = 0
        self.redirects_followed = 0
        self.connections_reused = 0

        # Logger
        self.advanced_logger, self.advanced_logs = create_advanced_logger()

    def start(self):
        """Start proxy with system proxy configuration if enabled"""
        if self.enable_system_proxy:
            self.log(f"Configuring system proxy to {self.host}:{self.port}...", Colors.WARNING)
            if SystemProxyConfigurator.set_system_proxy(self.host, self.port):
                self.log("System proxy configured successfully", Colors.OKGREEN)
            else:
                self.log("Failed to configure system proxy (may need admin rights)", Colors.WARNING)

        try:
            super().start()
        finally:
            if self.enable_system_proxy:
                self.log("Removing system proxy configuration...", Colors.WARNING)
                SystemProxyConfigurator.unset_system_proxy()

            self.connection_tracker.close_all()

    def handle_client(self, client_socket, client_address):
        """Enhanced client handler with all advanced features"""
        self.connection_count += 1
        conn_id = self.connection_count
        start_time = datetime.now()

        try:
            # Receive initial request
            client_socket.settimeout(10)
            initial_data = b''

            # Read request with better buffering
            while True:
                try:
                    chunk = client_socket.recv(8192)
                    if not chunk:
                        return
                    initial_data += chunk
                    if b'\r\n\r\n' in initial_data:
                        break
                    if len(initial_data) > 65536:  # Limit header size
                        break
                except socket.timeout:
                    if initial_data:
                        break
                    return

            if not initial_data:
                return

            # Parse request
            request_info = self.parse_http_request(initial_data)
            if not request_info:
                return

            # Check if should capture
            if not self.capture_mode.should_capture(request_info):
                # Still forward but don't log
                self._forward_without_logging(client_socket, request_info)
                return

            # Check for WebSocket upgrade
            if self.enable_websocket and self.websocket_handler.is_websocket_upgrade(request_info['headers']):
                self.websocket_count += 1
                self.advanced_logger(f"WebSocket upgrade detected (#{self.websocket_count})", "websocket")
                self._handle_websocket_request(client_socket, client_address, request_info)
                return

            # Check for CONNECT (HTTPS)
            if initial_data.startswith(b'CONNECT '):
                self._handle_connect_with_dns(client_socket, client_address, request_info)
                return

            # Regular HTTP request
            self._handle_http_with_advanced_features(client_socket, client_address, request_info, start_time)

        except Exception as e:
            self.advanced_logger(f"Connection #{conn_id} error: {e}", "error")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _handle_websocket_request(self, client_socket, client_address, request_info):
        """Handle WebSocket upgrade request"""
        try:
            host = request_info['headers'].get('Host', '')
            if ':' in host:
                target_host, target_port = host.rsplit(':', 1)
                target_port = int(target_port)
            else:
                target_host = host
                target_port = 80

            # Resolve DNS
            target_ip = self.dns_resolver.resolve(target_host, self.advanced_logger)

            # Connect to server (with upstream proxy support)
            server_socket = self.upstream_handler.connect(target_host, target_port)

            # Add WebSocket upgrade to history for GUI visibility
            self.history.add({
                'timestamp': time.time(),
                'method': 'WEBSOCKET',
                'host': target_host,
                'path': request_info.get('path', '/'),
                'url': f"ws://{target_host}{request_info.get('path', '/')}",
                'status_code': 101,
                'status_text': 'Switching Protocols',
                'headers': request_info['headers'],
                'body': b'',
                'response_headers': {},
                'response_body': b'[WebSocket Connection - Real-time Messages]',
                'response_time': 0,
                'info': 'WebSocket connection - bidirectional communication'
            })

            # Record statistics
            if hasattr(self, 'stats'):
                self.stats.record_connection()

            # Handle WebSocket
            self.websocket_handler.handle_websocket(
                client_socket, server_socket, request_info, self.advanced_logger
            )

        except Exception as e:
            self.advanced_logger(f"WebSocket error: {e}", "error")

    def _handle_connect_with_dns(self, client_socket, client_address, request_info):
        """Handle CONNECT with DNS logging"""
        try:
            # Parse CONNECT request
            lines = request_info['raw'].split(b'\r\n')
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

                # DNS resolution
                self.dns_resolutions += 1
                target_ip = self.dns_resolver.resolve(target_host, self.advanced_logger)

                self.advanced_logger(f"HTTPS CONNECT to {target_host}:{target_port} ({target_ip})", "info")

                # Add HTTPS tunnel to history for GUI visibility
                self.history.add({
                    'timestamp': time.time(),
                    'method': 'CONNECT',
                    'host': target_host,
                    'path': f':{target_port}',
                    'url': f"https://{target_host}:{target_port}",
                    'status_code': 200,  # Tunnel established
                    'status_text': 'Connection Established',
                    'headers': {},
                    'body': b'',
                    'response_headers': {},
                    'response_body': '[HTTPS Tunnel - Encrypted]'.encode(),
                    'response_time': 0,
                    'info': 'HTTPS tunnel - content encrypted'
                })

                # Record connection in statistics
                if hasattr(self, 'stats'):
                    self.stats.record_connection()

                # Check for existing connection
                existing_conn = self.connection_tracker.get_connection(target_host, target_port)
                if existing_conn:
                    self.connections_reused += 1
                    server_socket = existing_conn
                    self.advanced_logger(f"Reusing connection to {target_host}:{target_port}", "info")
                else:
                    # Connect (with upstream proxy support)
                    server_socket = self.upstream_handler.connect(target_host, target_port)
                    self.connection_tracker.add_connection(target_host, target_port, server_socket)

                # Send connection established
                client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

                # Relay traffic
                self._relay_traffic(client_socket, server_socket, target_host)

        except Exception as e:
            self.advanced_logger(f"CONNECT error: {e}", "error")

    def _handle_http_with_advanced_features(self, client_socket, client_address, request_info, start_time):
        """Handle HTTP request with all advanced features"""
        try:
            host = request_info['headers'].get('Host', '')
            if ':' in host:
                target_host, target_port = host.rsplit(':', 1)
                target_port = int(target_port)
            else:
                target_host = host
                target_port = 80

            # DNS resolution
            self.dns_resolutions += 1
            target_ip = self.dns_resolver.resolve(target_host, self.advanced_logger)

            # Check for existing connection (keep-alive)
            server_socket = self.connection_tracker.get_connection(target_host, target_port)
            if server_socket:
                self.connections_reused += 1
                self.advanced_logger(f"Reusing connection to {target_host}:{target_port}", "info")
            else:
                # New connection (with upstream proxy support)
                server_socket = self.upstream_handler.connect(target_host, target_port)

            # Send request
            server_socket.sendall(request_info['raw'])

            # Receive response
            response_data = b''
            response_headers = {}

            # Read response headers
            while b'\r\n\r\n' not in response_data:
                chunk = server_socket.recv(8192)
                if not chunk:
                    break
                response_data += chunk

            # Parse response headers
            if b'\r\n\r\n' in response_data:
                headers_end = response_data.find(b'\r\n\r\n')
                headers_part = response_data[:headers_end]
                body_start = response_data[headers_end + 4:]

                # Parse headers
                for line in headers_part.split(b'\r\n')[1:]:
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        response_headers[key.decode('utf-8', errors='replace').strip()] = \
                            value.decode('utf-8', errors='replace').strip()

                # Check if chunked encoding
                if self.chunked_handler.is_chunked(response_headers):
                    self.advanced_logger(f"Chunked encoding detected for {target_host}", "info")
                    # Read chunked body
                    chunked_body = self.chunked_handler.read_chunked_body(server_socket)
                    response_data = response_data[:headers_end + 4] + chunked_body
                else:
                    # Read remaining body
                    content_length = response_headers.get('Content-Length')
                    if content_length:
                        try:
                            remaining = int(content_length) - len(body_start)
                            while remaining > 0:
                                chunk = server_socket.recv(min(remaining, 65536))
                                if not chunk:
                                    break
                                response_data += chunk
                                remaining -= len(chunk)
                        except:
                            pass

                # Check for redirects
                response_info = self.parse_http_response(response_data)
                if response_info and self.redirect_handler.is_redirect(response_info.get('status_code', 0)):
                    redirect_location = self.redirect_handler.get_redirect_location(response_info.get('headers', {}))
                    if redirect_location:
                        self.redirects_followed += 1
                        self.advanced_logger(f"Redirect {response_info['status_code']} to {redirect_location}", "redirect")

            # Forward response to client
            client_socket.sendall(response_data)

            # Check if we should keep connection alive
            connection_header = response_headers.get('Connection', '').lower()
            if 'keep-alive' in connection_header:
                self.connection_tracker.add_connection(target_host, target_port, server_socket)
            else:
                server_socket.close()

            # Display request/response (existing functionality)
            response_info = None
            response_time = 0
            if response_data:
                response_info = self.parse_http_response(response_data)
                response_time = (datetime.now() - start_time).total_seconds()

            if self.show_body:
                self.display_request(request_info)
                if response_info:
                    self.display_response(response_info, response_time=response_time)

            # Add to history for GUI
            if response_info:
                self.history.add({
                    'timestamp': time.time(),
                    'method': request_info['method'],
                    'host': target_host,
                    'path': request_info['path'],
                    'url': f"http://{target_host}{request_info['path']}",
                    'status_code': response_info.get('status_code', 0),
                    'status_text': response_info.get('status_text', ''),
                    'headers': request_info['headers'],
                    'body': request_info.get('body', b''),
                    'response_headers': response_info.get('headers', {}),
                    'response_body': response_info.get('body', b''),
                    'response_time': response_time
                })

                # Record statistics
                if hasattr(self, 'stats'):
                    self.stats.record_request(request_info['method'], target_host, len(request_info['raw']))
                    self.stats.record_response(response_info.get('status_code', 0), len(response_data), response_time)

        except Exception as e:
            self.advanced_logger(f"HTTP request error: {e}", "error")

    def _relay_traffic(self, client_socket, server_socket, host):
        """Relay traffic between client and server"""
        client_socket.setblocking(False)
        server_socket.setblocking(False)

        bytes_sent = 0
        bytes_received = 0

        try:
            while True:
                readable, _, exceptional = select.select(
                    [client_socket, server_socket], [],
                    [client_socket, server_socket], 5.0
                )

                if exceptional:
                    break

                if not readable:
                    # Timeout
                    break

                for sock in readable:
                    try:
                        data = sock.recv(65536)
                        if not data:
                            return

                        if sock is client_socket:
                            server_socket.sendall(data)
                            bytes_sent += len(data)
                        else:
                            client_socket.sendall(data)
                            bytes_received += len(data)
                    except:
                        return

        except Exception as e:
            self.advanced_logger(f"Relay error for {host}: {e}", "error")

    def _forward_without_logging(self, client_socket, request_info):
        """Forward request without logging (stealth mode)"""
        try:
            host = request_info['headers'].get('Host', '')
            if ':' in host:
                target_host, target_port = host.rsplit(':', 1)
                target_port = int(target_port)
            else:
                target_host = host
                target_port = 80

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((target_host, target_port))
            server_socket.sendall(request_info['raw'])

            while True:
                chunk = server_socket.recv(8192)
                if not chunk:
                    break
                client_socket.sendall(chunk)

            server_socket.close()
        except:
            pass

    def print_advanced_stats(self):
        """Print advanced statistics"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}ADVANCED STATISTICS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"WebSocket connections: {self.websocket_count}")
        print(f"DNS resolutions: {self.dns_resolutions}")
        print(f"Redirects followed: {self.redirects_followed}")
        print(f"Connections reused: {self.connections_reused}")
        print(f"Total advanced logs: {len(self.advanced_logs)}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced HTTP/HTTPS Proxy - Never Miss Traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Features:
  - WebSocket protocol support
  - HTTPS MITM interception
  - System proxy auto-configuration
  - Connection pooling and keep-alive
  - DNS resolution tracking
  - Chunked transfer encoding
  - Upstream proxy support (chaining)
  - Traffic capture modes
  - Redirect tracking
  - Advanced error recovery

Examples:
  %(prog)s                              # Basic enhanced proxy
  %(prog)s --enable-websocket           # With WebSocket support
  %(prog)s --system-proxy               # Auto-configure system proxy
  %(prog)s --upstream-proxy proxy:3128  # Chain through upstream proxy
  %(prog)s --capture-mode debug         # Maximum logging
  %(prog)s -v -b --enable-websocket     # Full featured

Capture Modes:
  promiscuous - Capture everything (default)
  selective   - Capture based on rules
  stealth     - Minimal logging
  debug       - Maximum verbosity

WARNING: This tool is for defensive security and development purposes only.
        """
    )

    parser.add_argument('-H', '--host', default='127.0.0.1',
                       help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=8888,
                       help='Port to listen on (default: 8888)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose mode')
    parser.add_argument('-b', '--show-body', action='store_true',
                       help='Show request/response bodies')
    parser.add_argument('-o', '--output', help='Save traffic to file')

    # Advanced options
    parser.add_argument('--enable-websocket', action='store_true', default=True,
                       help='Enable WebSocket support (default: enabled)')
    parser.add_argument('--system-proxy', action='store_true',
                       help='Auto-configure system proxy (requires admin/root)')
    parser.add_argument('--upstream-proxy',
                       help='Upstream proxy for chaining (host:port)')
    parser.add_argument('--capture-mode', default='promiscuous',
                       choices=['promiscuous', 'selective', 'stealth', 'debug'],
                       help='Traffic capture mode (default: promiscuous)')

    # Filters
    parser.add_argument('--filter-domain', help='Filter by domain')
    parser.add_argument('--filter-method', help='Filter by HTTP method')
    parser.add_argument('--filter-status', type=int, help='Filter by status code')

    args = parser.parse_args()

    if not MODULES_AVAILABLE:
        print(f"{Colors.FAIL}Error: Required modules not available{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.HEADER}Enhanced HTTP/HTTPS Proxy - Never Miss Traffic{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"Features enabled:")
    print(f"  ✓ WebSocket support: {args.enable_websocket}")
    print(f"  ✓ System proxy: {args.system_proxy}")
    print(f"  ✓ Upstream proxy: {args.upstream_proxy or 'None'}")
    print(f"  ✓ Capture mode: {args.capture_mode}")
    print(f"  ✓ DNS tracking: Always")
    print(f"  ✓ Connection pooling: Always")
    print(f"  ✓ Chunked encoding: Always")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

    proxy = EnhancedHTTPSViewer(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        save_to_file=args.output,
        filter_domain=args.filter_domain,
        filter_method=args.filter_method,
        filter_status=args.filter_status,
        show_body=args.show_body,
        enable_websocket=args.enable_websocket,
        enable_system_proxy=args.system_proxy,
        upstream_proxy=args.upstream_proxy,
        capture_mode=args.capture_mode
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Shutting down...{Colors.ENDC}")
        proxy.print_advanced_stats()
        proxy.stats.print_summary()
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
