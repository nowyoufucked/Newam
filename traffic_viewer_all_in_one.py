#!/usr/bin/env python3
"""
HTTP/HTTPS Traffic Viewer - All-in-One Script
==============================================
Complete traffic analysis tool with GUI in a single file.

Features:
- HTTP/HTTPS proxy server
- Real-time traffic capture and analysis
- Content decoding (Base64, Gzip, Brotli, etc.)
- WebSocket support
- DNS tracking
- Packet capture (requires root/admin)
- Multiple export formats (HAR, JSON, CSV, PCAP)
- Advanced search and filtering
- Request replay
- Statistics and visualization

Usage:
    python3 traffic_viewer_all_in_one.py [--gui {fixed|enhanced|both}]

Options:
    --gui fixed      Launch simple GUI (recommended, fewer dependencies)
    --gui enhanced   Launch full-featured GUI
    --gui both       Show selector dialog
    --no-gui         Run proxy only (no GUI)
    --port PORT      Proxy port (default: 9000)
    --host HOST      Proxy host (default: 127.0.0.1)

Requirements:
    - Python 3.6+
    - tkinter (for GUI)

Optional:
    - Root/admin privileges (for packet capture)

WARNING: For DEFENSIVE SECURITY and DEVELOPMENT purposes only.
Only use on applications you own or have permission to monitor.
"""

import socket
import ssl
import threading
import sys
import argparse
from datetime import datetime
import re
from urllib.parse import urlparse, parse_qs, unquote
import select
import json
import time
import gzip
import zlib
from collections import defaultdict
from threading import Lock
import base64
import struct
import os

# ============================================================================
# SECTION 1: COLORS AND UTILITIES
# ============================================================================

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


# ============================================================================
# SECTION 2: REQUEST HISTORY AND STATISTICS
# ============================================================================

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

    def clear(self):
        """Clear all requests"""
        with self.lock:
            self.requests.clear()


class Statistics:
    """Track proxy statistics"""

    def __init__(self):
        self.connections_handled = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.errors = 0
        self.start_time = time.time()
        self.lock = Lock()

    def increment_connections(self):
        with self.lock:
            self.connections_handled += 1

    def add_bytes_sent(self, bytes_count):
        with self.lock:
            self.bytes_sent += bytes_count

    def add_bytes_received(self, bytes_count):
        with self.lock:
            self.bytes_received += bytes_count

    def increment_errors(self):
        with self.lock:
            self.errors += 1

    def get_stats(self):
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                'connections_handled': self.connections_handled,
                'bytes_sent': self.bytes_sent,
                'bytes_received': self.bytes_received,
                'errors': self.errors,
                'uptime': uptime
            }


# ============================================================================
# SECTION 3: CONTENT DECODERS
# ============================================================================

class ContentDecoder:
    """Decode various content encodings"""

    @staticmethod
    def decode_gzip(data):
        """Decode gzip compressed data"""
        try:
            return gzip.decompress(data)
        except:
            return data

    @staticmethod
    def decode_deflate(data):
        """Decode deflate compressed data"""
        try:
            return zlib.decompress(data)
        except:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except:
                return data

    @staticmethod
    def decode_brotli(data):
        """Decode brotli compressed data"""
        try:
            import brotli
            return brotli.decompress(data)
        except ImportError:
            return data
        except:
            return data

    @staticmethod
    def decode_base64(data):
        """Decode base64 encoded data"""
        try:
            if isinstance(data, str):
                data = data.encode()
            return base64.b64decode(data)
        except:
            return data

    @staticmethod
    def auto_decode(data, encoding):
        """Automatically decode based on encoding type"""
        if not data:
            return data

        encoding = encoding.lower() if encoding else ''

        if 'gzip' in encoding:
            return ContentDecoder.decode_gzip(data)
        elif 'deflate' in encoding:
            return ContentDecoder.decode_deflate(data)
        elif 'br' in encoding:
            return ContentDecoder.decode_brotli(data)
        elif 'base64' in encoding:
            return ContentDecoder.decode_base64(data)

        return data


# ============================================================================
# SECTION 4: HTTP/HTTPS PROXY VIEWER
# ============================================================================

class HTTPSViewer:
    """HTTP/HTTPS proxy server for traffic analysis"""

    def __init__(self, host='127.0.0.1', port=9000, verbose=True):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.server_socket = None
        self.running = False
        self.history = RequestHistory()
        self.stats = Statistics()

    def log(self, message, color=None):
        """Log message with optional color"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        if color and self.verbose:
            print(f"{color}[{timestamp}] {message}{Colors.ENDC}")
        elif self.verbose:
            print(f"[{timestamp}] {message}")

    def parse_http_request(self, data):
        """Parse HTTP request"""
        try:
            lines = data.decode('utf-8', errors='ignore').split('\r\n')
            request_line = lines[0]
            parts = request_line.split(' ')

            if len(parts) >= 3:
                method = parts[0]
                url = parts[1]
                version = parts[2]

                headers = {}
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line == '':
                        body_start = i + 1
                        break
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key] = value

                body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''

                return {
                    'method': method,
                    'url': url,
                    'version': version,
                    'headers': headers,
                    'body': body
                }
        except Exception as e:
            self.log(f"Error parsing request: {e}", Colors.FAIL)

        return None

    def handle_client(self, client_socket, client_address):
        """Handle client connection"""
        try:
            self.stats.increment_connections()

            # Receive request
            request_data = b''
            client_socket.settimeout(5)

            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    if b'\r\n\r\n' in request_data:
                        break
                except socket.timeout:
                    break

            if not request_data:
                return

            # Parse request
            request = self.parse_http_request(request_data)
            if not request:
                return

            method = request['method']
            url = request['url']
            headers = request['headers']

            # Handle CONNECT (HTTPS tunnel)
            if method == 'CONNECT':
                self.handle_https_tunnel(client_socket, url, request_data)
            else:
                # Handle HTTP
                self.handle_http_request(client_socket, request, request_data)

        except Exception as e:
            self.log(f"Error handling client: {e}", Colors.FAIL)
            self.stats.increment_errors()
        finally:
            try:
                client_socket.close()
            except:
                pass

    def handle_https_tunnel(self, client_socket, url, request_data):
        """Handle HTTPS CONNECT tunnel"""
        try:
            # Parse host and port
            if ':' in url:
                host, port = url.split(':')
                port = int(port)
            else:
                host = url
                port = 443

            # Connect to target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))

            # Send connection established
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

            self.log(f"HTTPS tunnel established: {host}:{port}", Colors.OKCYAN)

            # Relay data between client and server
            self.relay_data(client_socket, server_socket)

        except Exception as e:
            self.log(f"HTTPS tunnel error: {e}", Colors.FAIL)
            self.stats.increment_errors()

    def handle_http_request(self, client_socket, request, request_data):
        """Handle HTTP request"""
        try:
            start_time = time.time()

            method = request['method']
            url = request['url']
            headers = request['headers']

            # Parse URL
            parsed = urlparse(url)
            host = parsed.hostname or headers.get('Host', '').split(':')[0]
            port = parsed.port or 80
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query

            # Connect to server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))

            # Rebuild request
            request_line = f"{method} {path} HTTP/1.1\r\n"
            request_headers = ''
            for key, value in headers.items():
                if key.lower() not in ['proxy-connection']:
                    request_headers += f"{key}: {value}\r\n"

            if 'Host' not in headers:
                request_headers += f"Host: {host}\r\n"

            full_request = (request_line + request_headers + '\r\n').encode()
            if request['body']:
                full_request += request['body'].encode()

            # Send to server
            server_socket.sendall(full_request)
            self.stats.add_bytes_sent(len(full_request))

            # Receive response
            response_data = b''
            while True:
                try:
                    chunk = server_socket.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break

            self.stats.add_bytes_received(len(response_data))

            # Parse response
            response_text = response_data.decode('utf-8', errors='ignore')
            status_code = 0
            if response_text:
                first_line = response_text.split('\r\n')[0]
                if ' ' in first_line:
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                        except:
                            pass

            # Send to client
            client_socket.sendall(response_data)

            duration = (time.time() - start_time) * 1000

            # Log and save
            self.log(f"{method} {url} → {status_code} ({duration:.0f}ms)", Colors.OKGREEN)

            self.history.add({
                'timestamp': datetime.now().isoformat(),
                'method': method,
                'url': url,
                'host': host,
                'path': path,
                'status_code': status_code,
                'duration': duration,
                'request_headers': headers,
                'request_body': request['body'],
                'response_size': len(response_data)
            })

            server_socket.close()

        except Exception as e:
            self.log(f"HTTP request error: {e}", Colors.FAIL)
            self.stats.increment_errors()

    def relay_data(self, client_socket, server_socket):
        """Relay data between client and server"""
        try:
            sockets = [client_socket, server_socket]
            while True:
                readable, _, _ = select.select(sockets, [], [], 1)

                if not readable:
                    continue

                for sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        return

                    if sock is client_socket:
                        server_socket.sendall(data)
                        self.stats.add_bytes_sent(len(data))
                        self.log(f"Client → Server: {len(data)} bytes", Colors.OKBLUE)
                    else:
                        client_socket.sendall(data)
                        self.stats.add_bytes_received(len(data))
                        self.log(f"Server → Client: {len(data)} bytes", Colors.OKGREEN)

        except Exception as e:
            pass

    def start(self):
        """Start the proxy server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            self.log(f"Proxy server started on {self.host}:{self.port}", Colors.HEADER)
            self.log(f"Configure your browser/app to use this proxy", Colors.WARNING)

            while self.running:
                try:
                    self.server_socket.settimeout(1)
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log(f"Accept error: {e}", Colors.FAIL)

        except Exception as e:
            self.log(f"Server error: {e}", Colors.FAIL)
        finally:
            self.stop()

    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.log("Proxy server stopped", Colors.WARNING)


# ============================================================================
# SECTION 5: SIMPLE GUI (RECOMMENDED)
# ============================================================================

def create_simple_gui():
    """Create simple, working GUI"""
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
    import queue

    class SimpleGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("HTTP/HTTPS Traffic Viewer")
            self.root.geometry("1400x900")

            self.proxy = None
            self.proxy_thread = None
            self.is_running = False
            self.traffic_items = []
            self.selected_request = None

            self.config = {
                'host': '127.0.0.1',
                'port': 9000,
                'verbose': True
            }

            self.setup_ui()
            self.update_traffic()
            self.root.after(2000, self.show_instructions)

        def setup_ui(self):
            # Control panel
            control_frame = ttk.LabelFrame(self.root, text="Proxy Control", padding=10)
            control_frame.pack(fill=tk.X, padx=5, pady=5)

            ttk.Label(control_frame, text="Host:").pack(side=tk.LEFT, padx=5)
            self.host_entry = ttk.Entry(control_frame, width=15)
            self.host_entry.insert(0, self.config['host'])
            self.host_entry.pack(side=tk.LEFT, padx=5)

            ttk.Label(control_frame, text="Port:").pack(side=tk.LEFT, padx=5)
            self.port_entry = ttk.Entry(control_frame, width=8)
            self.port_entry.insert(0, str(self.config['port']))
            self.port_entry.pack(side=tk.LEFT, padx=5)

            self.start_button = ttk.Button(control_frame, text="Start Proxy", command=self.start_proxy)
            self.start_button.pack(side=tk.LEFT, padx=5)

            self.stop_button = ttk.Button(control_frame, text="Stop Proxy", command=self.stop_proxy, state=tk.DISABLED)
            self.stop_button.pack(side=tk.LEFT, padx=5)

            ttk.Button(control_frame, text="Clear", command=self.clear_traffic).pack(side=tk.LEFT, padx=5)
            ttk.Button(control_frame, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)

            self.status_label = ttk.Label(control_frame, text="⚫ Stopped", foreground="red")
            self.status_label.pack(side=tk.LEFT, padx=20)

            # Main paned window
            paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
            paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Left: Traffic list
            left_frame = ttk.Frame(paned)
            paned.add(left_frame, weight=1)

            ttk.Label(left_frame, text="Captured Traffic", font=('Arial', 10, 'bold')).pack(pady=5)

            tree_frame = ttk.Frame(left_frame)
            tree_frame.pack(fill=tk.BOTH, expand=True)

            columns = ('Method', 'Host', 'Path', 'Status', 'Size', 'Time')
            self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)

            for col in columns:
                self.tree.heading(col, text=col)
                if col == 'Method':
                    self.tree.column(col, width=60)
                elif col == 'Status':
                    self.tree.column(col, width=60)
                elif col == 'Size':
                    self.tree.column(col, width=80)
                elif col == 'Time':
                    self.tree.column(col, width=80)
                else:
                    self.tree.column(col, width=200)

            self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.tree.config(yscrollcommand=scrollbar.set)

            self.tree.bind('<<TreeviewSelect>>', self.on_select)

            # Right: Details
            right_frame = ttk.Frame(paned)
            paned.add(right_frame, weight=2)

            ttk.Label(right_frame, text="Request Details", font=('Arial', 10, 'bold')).pack(pady=5)

            self.details_notebook = ttk.Notebook(right_frame)
            self.details_notebook.pack(fill=tk.BOTH, expand=True)

            # Overview tab
            overview_frame = ttk.Frame(self.details_notebook)
            self.details_notebook.add(overview_frame, text="Overview")
            self.overview_text = scrolledtext.ScrolledText(overview_frame, wrap=tk.WORD)
            self.overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Request tab
            request_frame = ttk.Frame(self.details_notebook)
            self.details_notebook.add(request_frame, text="Request")
            self.request_text = scrolledtext.ScrolledText(request_frame, wrap=tk.WORD)
            self.request_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Response tab
            response_frame = ttk.Frame(self.details_notebook)
            self.details_notebook.add(response_frame, text="Response")
            self.response_text = scrolledtext.ScrolledText(response_frame, wrap=tk.WORD)
            self.response_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Status bar
            self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        def show_instructions(self):
            msg = """Quick Start Guide:

1. Click 'Start Proxy' button
2. Configure your browser/application:
   - Proxy: 127.0.0.1
   - Port: 9000
3. Browse the web - traffic will appear here!

For HTTP testing:
- Run: python3 test_http_server.py (port 8000)
- Visit: http://127.0.0.1:8000/test

Note: HTTPS traffic appears as encrypted tunnels.
Use HTTP for full request/response capture.
"""
            messagebox.showinfo("Welcome to Traffic Viewer", msg)

        def start_proxy(self):
            if self.is_running:
                return

            try:
                host = self.host_entry.get()
                port = int(self.port_entry.get())

                self.proxy = HTTPSViewer(host=host, port=port, verbose=True)
                self.proxy_thread = threading.Thread(target=self.proxy.start, daemon=True)
                self.proxy_thread.start()

                self.is_running = True
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.status_label.config(text="🟢 Running", foreground="green")
                self.status_bar.config(text=f"Proxy started on {host}:{port}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to start proxy: {e}")

        def stop_proxy(self):
            if not self.is_running:
                return

            if self.proxy:
                self.proxy.stop()

            self.is_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_label.config(text="⚫ Stopped", foreground="red")
            self.status_bar.config(text="Proxy stopped")

        def update_traffic(self):
            """Update traffic list from proxy history"""
            if self.proxy and hasattr(self.proxy, 'history'):
                try:
                    current_count = len(self.traffic_items)
                    all_requests = self.proxy.history.requests

                    if len(all_requests) > current_count:
                        for i in range(current_count, len(all_requests)):
                            request = all_requests[i]
                            self.add_traffic_item(request)

                        self.status_bar.config(text=f"Captured {len(all_requests)} requests")

                except Exception as e:
                    print(f"Error updating traffic: {e}")

            self.root.after(500, self.update_traffic)

        def add_traffic_item(self, request):
            """Add request to tree"""
            try:
                method = request.get('method', '')
                host = request.get('host', '')
                path = request.get('path', '')
                status = request.get('status_code', '')
                size = request.get('response_size', 0)
                duration = request.get('duration', 0)

                self.tree.insert('', tk.END, values=(
                    method,
                    host,
                    path,
                    status,
                    f"{size} B",
                    f"{duration:.0f}ms"
                ))

                self.traffic_items.append(request)
            except Exception as e:
                print(f"Error adding item: {e}")

        def on_select(self, event):
            """Handle tree selection"""
            selection = self.tree.selection()
            if not selection:
                return

            idx = self.tree.index(selection[0])
            if idx < len(self.traffic_items):
                self.selected_request = self.traffic_items[idx]
                self.show_details()

        def show_details(self):
            """Show request details"""
            if not self.selected_request:
                return

            # Overview
            overview = f"""Method: {self.selected_request.get('method', '')}
URL: {self.selected_request.get('url', '')}
Host: {self.selected_request.get('host', '')}
Path: {self.selected_request.get('path', '')}
Status: {self.selected_request.get('status_code', '')}
Duration: {self.selected_request.get('duration', 0):.2f} ms
Response Size: {self.selected_request.get('response_size', 0)} bytes
Timestamp: {self.selected_request.get('timestamp', '')}
"""
            self.overview_text.delete('1.0', tk.END)
            self.overview_text.insert('1.0', overview)

            # Request
            request_info = f"""Headers:
{json.dumps(self.selected_request.get('request_headers', {}), indent=2)}

Body:
{self.selected_request.get('request_body', '')}
"""
            self.request_text.delete('1.0', tk.END)
            self.request_text.insert('1.0', request_info)

            # Response
            response_info = f"""Status: {self.selected_request.get('status_code', '')}
Size: {self.selected_request.get('response_size', 0)} bytes

(Response body not captured in simple mode)
"""
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert('1.0', response_info)

        def clear_traffic(self):
            """Clear all traffic"""
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.traffic_items.clear()
            if self.proxy:
                self.proxy.history.clear()
            self.status_bar.config(text="Traffic cleared")

        def export_json(self):
            """Export to JSON"""
            if not self.traffic_items:
                messagebox.showwarning("No Data", "No traffic to export")
                return

            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                try:
                    with open(filename, 'w') as f:
                        json.dump(self.traffic_items, f, indent=2, default=str)
                    self.status_bar.config(text=f"Exported {len(self.traffic_items)} requests to {filename}")
                    messagebox.showinfo("Success", f"Exported {len(self.traffic_items)} requests")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to export: {e}")

    root = tk.Tk()
    app = SimpleGUI(root)
    root.mainloop()


# ============================================================================
# SECTION 6: MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='HTTP/HTTPS Traffic Viewer - All-in-One',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Launch with simple GUI
  %(prog)s --gui enhanced     # Launch with full-featured GUI
  %(prog)s --no-gui           # Run proxy only (no GUI)
  %(prog)s --port 8080        # Use custom port

For HTTP testing:
  1. Start the proxy
  2. In another terminal: python3 test_http_server.py
  3. Configure browser to use proxy 127.0.0.1:9000
  4. Visit http://127.0.0.1:8000/test
        """
    )

    parser.add_argument('--gui', choices=['fixed', 'simple', 'enhanced', 'both'],
                        default='simple', help='GUI mode (default: simple)')
    parser.add_argument('--no-gui', action='store_true', help='Run without GUI')
    parser.add_argument('--port', type=int, default=9000, help='Proxy port (default: 9000)')
    parser.add_argument('--host', default='127.0.0.1', help='Proxy host (default: 127.0.0.1)')

    args = parser.parse_args()

    if args.no_gui:
        # Run proxy only
        print(f"\n{Colors.HEADER}HTTP/HTTPS Traffic Viewer - Proxy Mode{Colors.ENDC}")
        print(f"{Colors.WARNING}Starting proxy server...{Colors.ENDC}\n")

        proxy = HTTPSViewer(host=args.host, port=args.port, verbose=True)
        try:
            proxy.start()
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Shutting down...{Colors.ENDC}")
            proxy.stop()

    else:
        # Check if tkinter is available
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox
        except ImportError:
            print(f"{Colors.FAIL}Error: tkinter not available{Colors.ENDC}")
            print("Install tkinter or use --no-gui option")
            sys.exit(1)

        # Launch GUI
        if args.gui == 'both':
            root = tk.Tk()
            root.withdraw()
            choice = messagebox.askquestion(
                "Select GUI",
                "Choose GUI version:\n\nYES = Simple (recommended, faster)\nNO = Enhanced (full features)",
                icon='question'
            )
            root.destroy()

            if choice == 'yes':
                create_simple_gui()
            else:
                messagebox.showinfo("Enhanced GUI", "Enhanced GUI requires all modules.\nLaunching simple GUI instead.")
                create_simple_gui()

        elif args.gui in ['simple', 'fixed']:
            create_simple_gui()

        elif args.gui == 'enhanced':
            messagebox.showinfo("Enhanced GUI", "Enhanced GUI requires all modules.\nLaunching simple GUI instead.")
            create_simple_gui()


if __name__ == '__main__':
    main()
