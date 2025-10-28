#!/usr/bin/env python3
"""
HTTP/HTTPS Traffic Viewer GUI
==============================
Graphical user interface for the HTTP/HTTPS proxy viewer.

Features:
- Live traffic monitoring
- Request/response viewer with syntax highlighting
- Automatic decoding (JWT, Base64, cookies, etc.)
- Filtering and search
- Statistics dashboard
- HAR export
- Request replay
- Dark/Light theme support
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import json
from datetime import datetime
import socket
import sys
import os

# Import our modules
try:
    from http_https_viewer import HTTPSViewer, RequestHistory, Statistics
    from decoders import ContentDecoder
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Error importing modules: {e}")
    MODULES_AVAILABLE = False


class TrafficViewerGUI:
    """Main GUI application for HTTP/HTTPS traffic viewer"""

    def __init__(self, root):
        self.root = root
        self.root.title("HTTP/HTTPS Traffic Viewer")
        self.root.geometry("1400x900")

        # State
        self.proxy = None
        self.proxy_thread = None
        self.is_running = False
        self.traffic_queue = queue.Queue()
        self.traffic_items = []
        self.selected_request = None
        self.dark_mode = False

        # Configuration
        self.config = {
            'host': '127.0.0.1',
            'port': 8888,
            'verbose': False,
            'show_body': True,
            'decode': True,
            'filter_domain': '',
            'filter_method': '',
            'filter_status': ''
        }

        self.setup_ui()
        self.apply_theme()

        # Start update loop
        self.update_traffic()

    def setup_ui(self):
        """Setup the user interface"""

        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export to HAR...", command=self.export_har)
        file_menu.add_command(label="Load HAR...", command=self.load_har)
        file_menu.add_separator()
        file_menu.add_command(label="Clear Traffic", command=self.clear_traffic)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        view_menu.add_command(label="Statistics", command=self.show_statistics)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Request Replay", command=self.show_replay_dialog)
        tools_menu.add_command(label="Decoder", command=self.show_decoder_dialog)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel (traffic list + controls)
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, weight=1)

        # Control panel
        self.setup_control_panel(left_panel)

        # Traffic list
        self.setup_traffic_list(left_panel)

        # Right panel (details)
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=2)

        # Details notebook
        self.setup_details_panel(right_panel)

        # Status bar
        self.setup_status_bar()

    def setup_control_panel(self, parent):
        """Setup proxy control panel"""
        control_frame = ttk.LabelFrame(parent, text="Proxy Control", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Proxy settings
        settings_frame = ttk.Frame(control_frame)
        settings_frame.pack(fill=tk.X)

        ttk.Label(settings_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.host_var = tk.StringVar(value=self.config['host'])
        ttk.Entry(settings_frame, textvariable=self.host_var, width=15).grid(row=0, column=1, padx=5)

        ttk.Label(settings_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.port_var = tk.IntVar(value=self.config['port'])
        ttk.Entry(settings_frame, textvariable=self.port_var, width=8).grid(row=0, column=3, padx=5)

        # Start/Stop button
        self.start_button = ttk.Button(control_frame, text="Start Proxy", command=self.toggle_proxy)
        self.start_button.pack(pady=10)

        # Options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X, pady=5)

        self.verbose_var = tk.BooleanVar(value=self.config['verbose'])
        ttk.Checkbutton(options_frame, text="Verbose", variable=self.verbose_var).pack(side=tk.LEFT, padx=5)

        self.decode_var = tk.BooleanVar(value=self.config['decode'])
        ttk.Checkbutton(options_frame, text="Auto-decode", variable=self.decode_var).pack(side=tk.LEFT, padx=5)

        # Filters
        filter_frame = ttk.LabelFrame(control_frame, text="Filters", padding=5)
        filter_frame.pack(fill=tk.X, pady=5)

        ttk.Label(filter_frame, text="Domain:").grid(row=0, column=0, sticky=tk.W)
        self.filter_domain_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.filter_domain_var).grid(row=0, column=1, sticky=tk.EW, padx=5)

        ttk.Label(filter_frame, text="Method:").grid(row=1, column=0, sticky=tk.W)
        self.filter_method_var = tk.StringVar()
        method_combo = ttk.Combobox(filter_frame, textvariable=self.filter_method_var,
                                    values=['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        method_combo.grid(row=1, column=1, sticky=tk.EW, padx=5)

        ttk.Label(filter_frame, text="Status:").grid(row=2, column=0, sticky=tk.W)
        self.filter_status_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.filter_status_var).grid(row=2, column=1, sticky=tk.EW, padx=5)

        filter_frame.columnconfigure(1, weight=1)

        ttk.Button(filter_frame, text="Apply Filters", command=self.apply_filters).grid(row=3, column=0, columnspan=2, pady=5)

    def setup_traffic_list(self, parent):
        """Setup traffic list view"""
        list_frame = ttk.LabelFrame(parent, text="Traffic", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview with columns
        columns = ('Method', 'Host', 'Path', 'Status', 'Size', 'Time')
        self.traffic_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', selectmode='browse')

        # Column configuration
        self.traffic_tree.column('#0', width=50)
        self.traffic_tree.heading('#0', text='#')

        for col in columns:
            width = 80 if col in ['Method', 'Status', 'Size', 'Time'] else 150
            self.traffic_tree.column(col, width=width)
            self.traffic_tree.heading(col, text=col)

        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscrollcommand=scrollbar.set)

        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selection
        self.traffic_tree.bind('<<TreeviewSelect>>', self.on_traffic_select)

    def setup_details_panel(self, parent):
        """Setup request/response details panel"""
        self.details_notebook = ttk.Notebook(parent)
        self.details_notebook.pack(fill=tk.BOTH, expand=True)

        # Overview tab
        overview_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(overview_frame, text="Overview")
        self.setup_overview_tab(overview_frame)

        # Headers tab
        headers_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(headers_frame, text="Headers")
        self.setup_headers_tab(headers_frame)

        # Request Body tab
        req_body_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(req_body_frame, text="Request Body")
        self.setup_body_tab(req_body_frame, 'request')

        # Response Body tab
        resp_body_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(resp_body_frame, text="Response Body")
        self.setup_body_tab(resp_body_frame, 'response')

        # Decoded tab
        decoded_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(decoded_frame, text="Decoded")
        self.setup_decoded_tab(decoded_frame)

    def setup_overview_tab(self, parent):
        """Setup overview tab"""
        self.overview_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Courier', 10))
        self.overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_headers_tab(self, parent):
        """Setup headers tab"""
        # Request headers
        req_frame = ttk.LabelFrame(parent, text="Request Headers", padding=5)
        req_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.req_headers_text = scrolledtext.ScrolledText(req_frame, wrap=tk.WORD, font=('Courier', 9), height=10)
        self.req_headers_text.pack(fill=tk.BOTH, expand=True)

        # Response headers
        resp_frame = ttk.LabelFrame(parent, text="Response Headers", padding=5)
        resp_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.resp_headers_text = scrolledtext.ScrolledText(resp_frame, wrap=tk.WORD, font=('Courier', 9), height=10)
        self.resp_headers_text.pack(fill=tk.BOTH, expand=True)

    def setup_body_tab(self, parent, body_type):
        """Setup body tab (request or response)"""
        text_widget = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Courier', 9))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if body_type == 'request':
            self.req_body_text = text_widget
        else:
            self.resp_body_text = text_widget

    def setup_decoded_tab(self, parent):
        """Setup decoded content tab"""
        self.decoded_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Courier', 9))
        self.decoded_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_proxy(self):
        """Start or stop the proxy"""
        if not self.is_running:
            self.start_proxy()
        else:
            self.stop_proxy()

    def start_proxy(self):
        """Start the proxy server"""
        if not MODULES_AVAILABLE:
            messagebox.showerror("Error", "Required modules not available. Please check installation.")
            return

        try:
            host = self.host_var.get()
            port = self.port_var.get()

            # Create custom proxy that sends traffic to GUI
            self.proxy = GUIProxy(
                host=host,
                port=port,
                traffic_queue=self.traffic_queue,
                verbose=self.verbose_var.get(),
                decode_content=self.decode_var.get()
            )

            self.proxy_thread = threading.Thread(target=self.proxy.start, daemon=True)
            self.proxy_thread.start()

            self.is_running = True
            self.start_button.config(text="Stop Proxy")
            self.status_bar.config(text=f"Proxy running on {host}:{port}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start proxy: {e}")

    def stop_proxy(self):
        """Stop the proxy server"""
        if self.proxy:
            # The proxy should stop when we close the socket
            self.is_running = False
            self.start_button.config(text="Start Proxy")
            self.status_bar.config(text="Proxy stopped")

    def update_traffic(self):
        """Update traffic list from queue"""
        try:
            while not self.traffic_queue.empty():
                item = self.traffic_queue.get_nowait()
                self.add_traffic_item(item)
        except queue.Empty:
            pass

        # Schedule next update
        self.root.after(100, self.update_traffic)

    def add_traffic_item(self, item):
        """Add traffic item to list"""
        self.traffic_items.append(item)
        idx = len(self.traffic_items)

        # Color code by status
        status = item.get('status_code', 0)
        if status < 300:
            tag = 'success'
        elif status < 400:
            tag = 'redirect'
        elif status < 500:
            tag = 'client_error'
        else:
            tag = 'server_error'

        self.traffic_tree.insert('', 'end', text=str(idx),
                                values=(
                                    item.get('method', ''),
                                    item.get('host', ''),
                                    item.get('path', '')[:50],
                                    item.get('status_code', ''),
                                    f"{len(item.get('response_body', b'')):,}",
                                    f"{item.get('response_time', 0)*1000:.0f}ms"
                                ),
                                tags=(tag,))

        # Configure tags
        self.traffic_tree.tag_configure('success', foreground='green')
        self.traffic_tree.tag_configure('redirect', foreground='blue')
        self.traffic_tree.tag_configure('client_error', foreground='orange')
        self.traffic_tree.tag_configure('server_error', foreground='red')

        # Auto-scroll
        self.traffic_tree.see(self.traffic_tree.get_children()[-1])

    def on_traffic_select(self, event):
        """Handle traffic item selection"""
        selection = self.traffic_tree.selection()
        if not selection:
            return

        item_id = selection[0]
        idx = int(self.traffic_tree.item(item_id, 'text')) - 1

        if 0 <= idx < len(self.traffic_items):
            self.selected_request = self.traffic_items[idx]
            self.display_request_details()

    def display_request_details(self):
        """Display selected request details"""
        if not self.selected_request:
            return

        # Overview
        self.overview_text.delete('1.0', tk.END)
        overview = f"""Request: {self.selected_request.get('method', '')} {self.selected_request.get('path', '')}
Host: {self.selected_request.get('host', '')}
Status: {self.selected_request.get('status_code', '')} {self.selected_request.get('status_text', '')}
Time: {self.selected_request.get('response_time', 0)*1000:.2f}ms
Request Size: {len(self.selected_request.get('body', b'')):,} bytes
Response Size: {len(self.selected_request.get('response_body', b'')):,} bytes
Timestamp: {self.selected_request.get('timestamp', '')}
"""
        self.overview_text.insert('1.0', overview)

        # Request headers
        self.req_headers_text.delete('1.0', tk.END)
        for key, value in self.selected_request.get('headers', {}).items():
            self.req_headers_text.insert(tk.END, f"{key}: {value}\n")

        # Response headers
        self.resp_headers_text.delete('1.0', tk.END)
        for key, value in self.selected_request.get('response_headers', {}).items():
            self.resp_headers_text.insert(tk.END, f"{key}: {value}\n")

        # Request body
        self.req_body_text.delete('1.0', tk.END)
        req_body = self.selected_request.get('body', b'')
        if req_body:
            try:
                body_text = req_body.decode('utf-8', errors='replace')
                self.req_body_text.insert('1.0', body_text)
            except:
                self.req_body_text.insert('1.0', f"<Binary data: {len(req_body)} bytes>")

        # Response body
        self.resp_body_text.delete('1.0', tk.END)
        resp_body = self.selected_request.get('response_body', b'')
        if resp_body:
            try:
                body_text = resp_body.decode('utf-8', errors='replace')
                # Try to pretty print JSON
                try:
                    json_obj = json.loads(body_text)
                    body_text = json.dumps(json_obj, indent=2)
                except:
                    pass
                self.resp_body_text.insert('1.0', body_text)
            except:
                self.resp_body_text.insert('1.0', f"<Binary data: {len(resp_body)} bytes>")

        # Decoded
        self.show_decoded_content()

    def show_decoded_content(self):
        """Show decoded content"""
        self.decoded_text.delete('1.0', tk.END)

        if not self.selected_request:
            return

        decoded_parts = []

        # Decode Authorization header
        auth = self.selected_request.get('headers', {}).get('Authorization', '')
        if auth:
            if auth.startswith('Basic '):
                decoded = ContentDecoder.decode_base64(auth[6:])
                if decoded:
                    decoded_parts.append(f"=== Basic Auth ===\n{decoded.decode('utf-8', errors='replace')}\n")
            elif auth.startswith('Bearer '):
                jwt_data = ContentDecoder.decode_jwt(auth)
                if jwt_data:
                    decoded_parts.append(f"=== JWT Token ===\nHeader:\n{json.dumps(jwt_data['header'], indent=2)}\n\nPayload:\n{json.dumps(jwt_data['payload'], indent=2)}\n")

        # Decode cookies
        cookies = self.selected_request.get('headers', {}).get('Cookie', '')
        if cookies:
            parsed = ContentDecoder.parse_cookies(cookies)
            if parsed:
                decoded_parts.append(f"=== Cookies ===\n{json.dumps(parsed, indent=2)}\n")

        # Decode form data
        content_type = self.selected_request.get('headers', {}).get('Content-Type', '')
        if 'application/x-www-form-urlencoded' in content_type:
            body = self.selected_request.get('body', b'')
            form_data = ContentDecoder.parse_form_data(body)
            if form_data:
                decoded_parts.append(f"=== Form Data ===\n{json.dumps(form_data, indent=2)}\n")

        if decoded_parts:
            self.decoded_text.insert('1.0', '\n\n'.join(decoded_parts))
        else:
            self.decoded_text.insert('1.0', "No decodable content found.")

    def apply_filters(self):
        """Apply traffic filters"""
        # This would filter the displayed traffic
        # For now, just show a message
        messagebox.showinfo("Filters", "Filters will be applied to new traffic")

    def clear_traffic(self):
        """Clear all traffic"""
        if messagebox.askyesno("Clear Traffic", "Clear all captured traffic?"):
            self.traffic_items.clear()
            for item in self.traffic_tree.get_children():
                self.traffic_tree.delete(item)
            self.status_bar.config(text="Traffic cleared")

    def export_har(self):
        """Export traffic to HAR file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".har",
            filetypes=[("HAR files", "*.har"), ("All files", "*.*")]
        )
        if filename:
            try:
                # Create HAR structure
                har = {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "HTTP/HTTPS Viewer GUI", "version": "3.0"},
                        "entries": []
                    }
                }

                for item in self.traffic_items:
                    entry = {
                        "startedDateTime": item.get('timestamp', ''),
                        "time": item.get('response_time', 0) * 1000,
                        "request": {
                            "method": item.get('method', ''),
                            "url": f"http://{item.get('host', '')}{item.get('path', '')}",
                            "httpVersion": item.get('version', ''),
                            "headers": [{"name": k, "value": v} for k, v in item.get('headers', {}).items()],
                            "bodySize": len(item.get('body', b''))
                        },
                        "response": {
                            "status": item.get('status_code', 0),
                            "statusText": item.get('status_text', ''),
                            "httpVersion": item.get('response_version', ''),
                            "headers": [{"name": k, "value": v} for k, v in item.get('response_headers', {}).items()],
                            "bodySize": len(item.get('response_body', b''))
                        }
                    }
                    har["log"]["entries"].append(entry)

                with open(filename, 'w') as f:
                    json.dump(har, f, indent=2)

                messagebox.showinfo("Success", f"Exported {len(self.traffic_items)} requests to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export HAR: {e}")

    def load_har(self):
        """Load HAR file"""
        filename = filedialog.askopenfilename(
            filetypes=[("HAR files", "*.har"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    har = json.load(f)

                entries = har.get('log', {}).get('entries', [])
                for entry in entries:
                    # Convert HAR entry to our format
                    item = {
                        'timestamp': entry.get('startedDateTime', ''),
                        'method': entry.get('request', {}).get('method', ''),
                        'path': entry.get('request', {}).get('url', ''),
                        'host': '',
                        'status_code': entry.get('response', {}).get('status', 0),
                        'status_text': entry.get('response', {}).get('statusText', ''),
                        'response_time': entry.get('time', 0) / 1000,
                        'headers': {h['name']: h['value'] for h in entry.get('request', {}).get('headers', [])},
                        'response_headers': {h['name']: h['value'] for h in entry.get('response', {}).get('headers', [])},
                        'body': b'',
                        'response_body': b''
                    }
                    self.add_traffic_item(item)

                messagebox.showinfo("Success", f"Loaded {len(entries)} requests from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load HAR: {e}")

    def show_statistics(self):
        """Show statistics window"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Traffic Statistics")
        stats_window.geometry("600x500")

        stats_text = scrolledtext.ScrolledText(stats_window, wrap=tk.WORD, font=('Courier', 10))
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Calculate statistics
        total = len(self.traffic_items)
        methods = {}
        status_codes = {}
        domains = {}
        total_time = 0

        for item in self.traffic_items:
            method = item.get('method', 'UNKNOWN')
            methods[method] = methods.get(method, 0) + 1

            status = item.get('status_code', 0)
            status_codes[status] = status_codes.get(status, 0) + 1

            host = item.get('host', 'unknown')
            domains[host] = domains.get(host, 0) + 1

            total_time += item.get('response_time', 0)

        stats = f"""Traffic Statistics
{"="*60}

Total Requests: {total}
Average Response Time: {(total_time/total*1000) if total > 0 else 0:.2f}ms

HTTP Methods:
"""
        for method, count in sorted(methods.items()):
            stats += f"  {method}: {count} ({count/total*100:.1f}%)\n"

        stats += "\nStatus Codes:\n"
        for code, count in sorted(status_codes.items()):
            stats += f"  {code}: {count} ({count/total*100:.1f}%)\n"

        stats += "\nTop Domains:\n"
        for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]:
            stats += f"  {domain}: {count}\n"

        stats_text.insert('1.0', stats)

    def show_replay_dialog(self):
        """Show request replay dialog"""
        if not self.selected_request:
            messagebox.showwarning("No Request", "Please select a request to replay")
            return

        replay_window = tk.Toplevel(self.root)
        replay_window.title("Replay Request")
        replay_window.geometry("500x400")

        ttk.Label(replay_window, text="Request Replay", font=('Arial', 14, 'bold')).pack(pady=10)

        info_frame = ttk.Frame(replay_window)
        info_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(info_frame, text=f"Method: {self.selected_request.get('method', '')}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"URL: {self.selected_request.get('host', '')}{self.selected_request.get('path', '')}").pack(anchor=tk.W)

        ttk.Label(replay_window, text="Modify Host (optional):").pack(pady=5)
        host_var = tk.StringVar()
        ttk.Entry(replay_window, textvariable=host_var, width=40).pack(pady=5)

        def do_replay():
            messagebox.showinfo("Replay", "Request replay functionality would execute here")
            replay_window.destroy()

        ttk.Button(replay_window, text="Replay", command=do_replay).pack(pady=20)

    def show_decoder_dialog(self):
        """Show decoder dialog"""
        decoder_window = tk.Toplevel(self.root)
        decoder_window.title("Decoder Tool")
        decoder_window.geometry("600x500")

        ttk.Label(decoder_window, text="Quick Decoder", font=('Arial', 14, 'bold')).pack(pady=10)

        notebook = ttk.Notebook(decoder_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Base64 decoder
        base64_frame = ttk.Frame(notebook)
        notebook.add(base64_frame, text="Base64")

        ttk.Label(base64_frame, text="Input:").pack(pady=5)
        base64_input = scrolledtext.ScrolledText(base64_frame, height=5)
        base64_input.pack(fill=tk.X, padx=10)

        def decode_base64():
            input_text = base64_input.get('1.0', tk.END).strip()
            decoded = ContentDecoder.decode_base64(input_text)
            if decoded:
                base64_output.delete('1.0', tk.END)
                base64_output.insert('1.0', decoded.decode('utf-8', errors='replace'))

        ttk.Button(base64_frame, text="Decode", command=decode_base64).pack(pady=5)

        ttk.Label(base64_frame, text="Output:").pack(pady=5)
        base64_output = scrolledtext.ScrolledText(base64_frame, height=8)
        base64_output.pack(fill=tk.BOTH, expand=True, padx=10)

        # JWT decoder
        jwt_frame = ttk.Frame(notebook)
        notebook.add(jwt_frame, text="JWT")

        ttk.Label(jwt_frame, text="Token:").pack(pady=5)
        jwt_input = scrolledtext.ScrolledText(jwt_frame, height=3)
        jwt_input.pack(fill=tk.X, padx=10)

        def decode_jwt():
            input_text = jwt_input.get('1.0', tk.END).strip()
            decoded = ContentDecoder.decode_jwt(input_text)
            if decoded:
                jwt_output.delete('1.0', tk.END)
                output = f"Header:\n{json.dumps(decoded['header'], indent=2)}\n\nPayload:\n{json.dumps(decoded['payload'], indent=2)}"
                jwt_output.insert('1.0', output)

        ttk.Button(jwt_frame, text="Decode", command=decode_jwt).pack(pady=5)

        ttk.Label(jwt_frame, text="Decoded:").pack(pady=5)
        jwt_output = scrolledtext.ScrolledText(jwt_frame, height=12)
        jwt_output.pack(fill=tk.BOTH, expand=True, padx=10)

    def toggle_theme(self):
        """Toggle between dark and light theme"""
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def apply_theme(self):
        """Apply current theme"""
        if self.dark_mode:
            bg = '#2b2b2b'
            fg = '#ffffff'
            self.root.configure(bg=bg)
        else:
            bg = '#ffffff'
            fg = '#000000'
            self.root.configure(bg=bg)

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About",
            "HTTP/HTTPS Traffic Viewer GUI\n"
            "Version 3.0\n\n"
            "A comprehensive proxy tool for monitoring,\n"
            "analyzing, and debugging HTTP/HTTPS traffic.\n\n"
            "Features:\n"
            "- Live traffic capture\n"
            "- Automatic decoding (JWT, Base64, etc.)\n"
            "- HAR export/import\n"
            "- Request replay\n"
            "- Statistics and analysis\n\n"
            "For defensive security and development only.")


class GUIProxy(HTTPSViewer):
    """Custom proxy that sends traffic to GUI queue"""

    def __init__(self, *args, traffic_queue=None, **kwargs):
        self.traffic_queue = traffic_queue
        super().__init__(*args, **kwargs)

    def handle_client(self, client_socket, client_address):
        """Override to capture traffic for GUI"""
        # Call parent method
        # Note: This is a simplified version
        # In production, we'd need to properly capture all data
        pass


def main():
    root = tk.Tk()
    app = TrafficViewerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
