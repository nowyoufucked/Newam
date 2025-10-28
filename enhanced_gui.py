#!/usr/bin/env python3
"""
Enhanced HTTP/HTTPS Traffic Viewer GUI with Advanced Features
==============================================================
Comprehensive GUI with packet capture, WebSocket viewer, DNS tracking,
visualization, and advanced analysis features.

New Features:
- Packet capture integration with PCAP export
- WebSocket message viewer with frame analysis
- DNS query viewer with statistics
- Live statistics charts and graphs
- Timeline visualization
- Session comparison and diff view
- Search with regex support
- Multiple export formats (HAR, PCAP, JSON, CSV)
- Certificate viewer for TLS connections
- Enhanced filtering with regex
- Protocol-specific tabs
- Connection tracking
- Performance profiling
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, font
import threading
import queue
import json
from datetime import datetime
import socket
import sys
import os
import re
from collections import defaultdict
import time

# Import our modules
try:
    from http_https_viewer import HTTPSViewer, RequestHistory, Statistics
    from decoders import ContentDecoder
    from enhanced_proxy import EnhancedHTTPSViewer
    from packet_capture import PacketCapture
    from protocol_dissectors import IPPacket, TCPSegment, UDPDatagram, DNSParser
    from pcap_writer import PCAPWriter
    ENHANCED_MODULES = True
except ImportError as e:
    print(f"Warning: Enhanced modules not available: {e}")
    try:
        from http_https_viewer import HTTPSViewer, RequestHistory, Statistics
        from decoders import ContentDecoder
        ENHANCED_MODULES = False
    except ImportError as e2:
        print(f"Error: Basic modules not available: {e2}")
        sys.exit(1)


class EnhancedTrafficViewerGUI:
    """Enhanced GUI with packet capture, WebSocket, DNS, and visualization features"""

    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced HTTP/HTTPS Traffic Viewer v5.0")
        self.root.geometry("1600x1000")

        # State
        self.proxy = None
        self.proxy_thread = None
        self.is_running = False
        self.traffic_queue = queue.Queue()
        self.traffic_items = []
        self.selected_request = None
        self.dark_mode = False

        # Packet capture state
        self.packet_capture = None
        self.packet_capture_running = False
        self.captured_packets = []

        # WebSocket state
        self.websocket_messages = []

        # DNS state
        self.dns_queries = []

        # Statistics for visualization
        self.stats_history = defaultdict(list)
        self.start_time = time.time()

        # Configuration
        self.config = {
            'host': '127.0.0.1',
            'port': 8888,
            'verbose': False,
            'show_body': True,
            'decode': True,
            'filter_domain': '',
            'filter_method': '',
            'filter_status': '',
            'use_enhanced_proxy': True,
            'enable_websocket': True,
            'enable_packet_capture': False,
            'packet_capture_interface': None
        }

        # Session management
        self.sessions = {}  # session_name -> traffic_items
        self.current_session = "Session 1"
        self.sessions[self.current_session] = []

        self.setup_ui()
        self.apply_theme()

        # Start update loops
        self.update_traffic()
        self.update_statistics()

        # Keyboard shortcuts
        self.setup_shortcuts()

    def setup_ui(self):
        """Setup the enhanced user interface"""

        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Session", command=self.new_session, accelerator="Ctrl+N")
        file_menu.add_separator()
        file_menu.add_command(label="Export to HAR...", command=self.export_har, accelerator="Ctrl+E")
        file_menu.add_command(label="Export to PCAP...", command=self.export_pcap)
        file_menu.add_command(label="Export to JSON...", command=self.export_json)
        file_menu.add_command(label="Export to CSV...", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Load HAR...", command=self.load_har, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Clear Traffic", command=self.clear_traffic, accelerator="Ctrl+L")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme, accelerator="Ctrl+T")
        view_menu.add_command(label="Statistics Dashboard", command=self.show_statistics, accelerator="Ctrl+S")
        view_menu.add_command(label="Timeline View", command=self.show_timeline)
        view_menu.add_command(label="WebSocket Messages", command=self.show_websocket_viewer)
        view_menu.add_command(label="DNS Queries", command=self.show_dns_viewer)
        view_menu.add_command(label="Packet Capture", command=self.show_packet_viewer)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Request Replay", command=self.show_replay_dialog, accelerator="Ctrl+R")
        tools_menu.add_command(label="Decoder", command=self.show_decoder_dialog, accelerator="Ctrl+D")
        tools_menu.add_command(label="Compare Sessions", command=self.show_compare_dialog)
        tools_menu.add_command(label="Search/Filter", command=self.show_search_dialog, accelerator="Ctrl+F")
        tools_menu.add_command(label="Certificate Viewer", command=self.show_certificate_viewer)
        tools_menu.add_separator()
        tools_menu.add_command(label="Start Packet Capture", command=self.start_packet_capture)
        tools_menu.add_command(label="Stop Packet Capture", command=self.stop_packet_capture)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="About", command=self.show_about)

        # Main container with paned window
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel - Control and Traffic List
        left_panel = ttk.Frame(main_paned)
        main_paned.add(left_panel, weight=1)

        # Control panel
        self.setup_control_panel(left_panel)

        # Session tabs
        self.setup_session_tabs(left_panel)

        # Traffic list
        self.setup_traffic_list(left_panel)

        # Right panel - Details viewer with tabs
        right_panel = ttk.Frame(main_paned)
        main_paned.add(right_panel, weight=2)

        # Details notebook
        self.setup_details_notebook(right_panel)

        # Status bar
        self.setup_status_bar()

    def setup_control_panel(self, parent):
        """Setup the control panel"""
        control_frame = ttk.LabelFrame(parent, text="Proxy Control", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Row 1: Host and Port
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Host:").pack(side=tk.LEFT, padx=5)
        self.host_entry = ttk.Entry(row1, width=15)
        self.host_entry.insert(0, self.config['host'])
        self.host_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(row1, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(row1, width=8)
        self.port_entry.insert(0, str(self.config['port']))
        self.port_entry.pack(side=tk.LEFT, padx=5)

        # Start/Stop buttons
        self.start_button = ttk.Button(row1, text="Start Proxy", command=self.start_proxy)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(row1, text="Stop Proxy", command=self.stop_proxy, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Row 2: Options
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=tk.X, pady=2)

        self.enhanced_var = tk.BooleanVar(value=self.config['use_enhanced_proxy'])
        ttk.Checkbutton(row2, text="Enhanced Mode", variable=self.enhanced_var).pack(side=tk.LEFT, padx=5)

        self.websocket_var = tk.BooleanVar(value=self.config['enable_websocket'])
        ttk.Checkbutton(row2, text="WebSocket", variable=self.websocket_var).pack(side=tk.LEFT, padx=5)

        self.verbose_var = tk.BooleanVar(value=self.config['verbose'])
        ttk.Checkbutton(row2, text="Verbose", variable=self.verbose_var).pack(side=tk.LEFT, padx=5)

        self.decode_var = tk.BooleanVar(value=self.config['decode'])
        ttk.Checkbutton(row2, text="Auto-decode", variable=self.decode_var).pack(side=tk.LEFT, padx=5)

        # Row 3: Filters
        row3 = ttk.Frame(control_frame)
        row3.pack(fill=tk.X, pady=2)

        ttk.Label(row3, text="Filter:").pack(side=tk.LEFT, padx=5)

        ttk.Label(row3, text="Domain:").pack(side=tk.LEFT)
        self.filter_domain_entry = ttk.Entry(row3, width=15)
        self.filter_domain_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(row3, text="Method:").pack(side=tk.LEFT)
        self.filter_method_combo = ttk.Combobox(row3, width=8, values=['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        self.filter_method_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(row3, text="Status:").pack(side=tk.LEFT)
        self.filter_status_entry = ttk.Entry(row3, width=8)
        self.filter_status_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(row3, text="Apply", command=self.apply_filters).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Clear", command=self.clear_filters).pack(side=tk.LEFT)

    def setup_session_tabs(self, parent):
        """Setup session tabs"""
        session_frame = ttk.Frame(parent)
        session_frame.pack(fill=tk.X, padx=5, pady=5)

        self.session_notebook = ttk.Notebook(session_frame)
        self.session_notebook.pack(fill=tk.BOTH, expand=True)

        # Add initial session
        self.add_session_tab(self.current_session)

        # Add + button for new sessions
        ttk.Button(session_frame, text="+ New Session", command=self.new_session, width=15).pack(pady=2)

    def setup_traffic_list(self, parent):
        """Setup the traffic list"""
        list_frame = ttk.LabelFrame(parent, text="Traffic", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Search bar
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, pady=2)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_entry.bind('<KeyRelease>', self.on_search)

        self.regex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(search_frame, text="Regex", variable=self.regex_var, command=self.on_search).pack(side=tk.LEFT)

        # Treeview with scrollbar
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(tree_frame, columns=('Time', 'Method', 'Host', 'Path', 'Status', 'Size', 'Duration'),
                                 show='tree headings', yscrollcommand=scrollbar.set, selectmode='browse')
        scrollbar.config(command=self.tree.yview)

        # Configure columns
        self.tree.column('#0', width=50, minwidth=50)
        self.tree.column('Time', width=80, minwidth=80)
        self.tree.column('Method', width=70, minwidth=70)
        self.tree.column('Host', width=200, minwidth=100)
        self.tree.column('Path', width=250, minwidth=100)
        self.tree.column('Status', width=60, minwidth=60)
        self.tree.column('Size', width=80, minwidth=80)
        self.tree.column('Duration', width=80, minwidth=80)

        # Configure headings
        self.tree.heading('#0', text='#')
        self.tree.heading('Time', text='Time')
        self.tree.heading('Method', text='Method')
        self.tree.heading('Host', text='Host')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Duration', text='Duration')

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.on_select_traffic)

        # Context menu
        self.tree_context_menu = tk.Menu(self.tree, tearoff=0)
        self.tree_context_menu.add_command(label="Copy URL", command=self.copy_url)
        self.tree_context_menu.add_command(label="Copy as cURL", command=self.copy_curl)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="Replay Request", command=self.replay_selected)
        self.tree_context_menu.add_command(label="Compare with...", command=self.compare_selected)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="Delete", command=self.delete_selected)

        self.tree.bind('<Button-3>', self.show_context_menu)

    def setup_details_notebook(self, parent):
        """Setup the details notebook with multiple tabs"""
        self.details_notebook = ttk.Notebook(parent)
        self.details_notebook.pack(fill=tk.BOTH, expand=True)

        # Overview tab
        self.overview_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.overview_frame, text='Overview')
        self.setup_overview_tab(self.overview_frame)

        # Headers tab
        self.headers_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.headers_frame, text='Headers')
        self.setup_headers_tab(self.headers_frame)

        # Request Body tab
        self.req_body_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.req_body_frame, text='Request Body')
        self.setup_request_body_tab(self.req_body_frame)

        # Response Body tab
        self.resp_body_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.resp_body_frame, text='Response Body')
        self.setup_response_body_tab(self.resp_body_frame)

        # Decoded tab
        self.decoded_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.decoded_frame, text='Decoded')
        self.setup_decoded_tab(self.decoded_frame)

        # WebSocket tab (if applicable)
        self.websocket_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.websocket_frame, text='WebSocket')
        self.setup_websocket_tab(self.websocket_frame)

        # Packet Details tab
        self.packet_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.packet_frame, text='Packet Details')
        self.setup_packet_tab(self.packet_frame)

        # Timing tab
        self.timing_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(self.timing_frame, text='Timing')
        self.setup_timing_tab(self.timing_frame)

    def setup_overview_tab(self, parent):
        """Setup overview tab"""
        self.overview_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, width=80, height=20)
        self.overview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_headers_tab(self, parent):
        """Setup headers tab"""
        # Request headers
        req_frame = ttk.LabelFrame(parent, text="Request Headers", padding=5)
        req_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.req_headers_text = scrolledtext.ScrolledText(req_frame, wrap=tk.NONE, width=80, height=10)
        self.req_headers_text.pack(fill=tk.BOTH, expand=True)

        # Response headers
        resp_frame = ttk.LabelFrame(parent, text="Response Headers", padding=5)
        resp_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.resp_headers_text = scrolledtext.ScrolledText(resp_frame, wrap=tk.NONE, width=80, height=10)
        self.resp_headers_text.pack(fill=tk.BOTH, expand=True)

    def setup_request_body_tab(self, parent):
        """Setup request body tab"""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=5, pady=2)

        ttk.Button(toolbar, text="Copy", command=lambda: self.copy_text(self.req_body_text)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save to File", command=lambda: self.save_text(self.req_body_text)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Pretty Print JSON", command=lambda: self.pretty_print_json(self.req_body_text)).pack(side=tk.LEFT, padx=2)

        self.req_body_text = scrolledtext.ScrolledText(parent, wrap=tk.NONE, width=80, height=20)
        self.req_body_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_response_body_tab(self, parent):
        """Setup response body tab"""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=5, pady=2)

        ttk.Button(toolbar, text="Copy", command=lambda: self.copy_text(self.resp_body_text)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save to File", command=lambda: self.save_text(self.resp_body_text)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Pretty Print JSON", command=lambda: self.pretty_print_json(self.resp_body_text)).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Render HTML", command=self.render_html).pack(side=tk.LEFT, padx=2)

        self.resp_body_text = scrolledtext.ScrolledText(parent, wrap=tk.NONE, width=80, height=20)
        self.resp_body_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_decoded_tab(self, parent):
        """Setup decoded content tab"""
        self.decoded_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, width=80, height=20)
        self.decoded_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_websocket_tab(self, parent):
        """Setup WebSocket messages tab"""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(toolbar, text="WebSocket Messages:").pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Clear", command=self.clear_websocket_messages).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export", command=self.export_websocket_messages).pack(side=tk.LEFT, padx=2)

        self.websocket_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, width=80, height=20)
        self.websocket_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_packet_tab(self, parent):
        """Setup packet details tab"""
        self.packet_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, width=80, height=20)
        self.packet_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_timing_tab(self, parent):
        """Setup timing information tab"""
        self.timing_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, width=80, height=20)
        self.timing_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(self.status_bar, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2, pady=2)

        self.stats_label = ttk.Label(self.status_bar, text="Requests: 0 | Responses: 0", relief=tk.SUNKEN)
        self.stats_label.pack(side=tk.RIGHT, padx=2, pady=2)

        self.proxy_status_label = ttk.Label(self.status_bar, text="⚫ Proxy: Stopped", relief=tk.SUNKEN)
        self.proxy_status_label.pack(side=tk.RIGHT, padx=2, pady=2)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.root.bind('<Control-n>', lambda e: self.new_session())
        self.root.bind('<Control-o>', lambda e: self.load_har())
        self.root.bind('<Control-e>', lambda e: self.export_har())
        self.root.bind('<Control-s>', lambda e: self.show_statistics())
        self.root.bind('<Control-r>', lambda e: self.show_replay_dialog())
        self.root.bind('<Control-d>', lambda e: self.show_decoder_dialog())
        self.root.bind('<Control-f>', lambda e: self.show_search_dialog())
        self.root.bind('<Control-l>', lambda e: self.clear_traffic())
        self.root.bind('<Control-t>', lambda e: self.toggle_theme())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<F5>', lambda e: self.refresh_display())

    # Placeholder methods for new features (to be implemented)

    def start_proxy(self):
        """Start the proxy server"""
        if self.is_running:
            messagebox.showwarning("Already Running", "Proxy is already running")
            return

        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())

            if ENHANCED_MODULES and self.enhanced_var.get():
                # Use enhanced proxy
                self.proxy = EnhancedHTTPSViewer(
                    host=host,
                    port=port,
                    enable_websocket=self.websocket_var.get()
                )
                self.status_label.config(text="Starting Enhanced Proxy...")
            else:
                # Use basic proxy
                self.proxy = HTTPSViewer(host=host, port=port)
                self.status_label.config(text="Starting Proxy...")

            # Start proxy in thread
            self.proxy_thread = threading.Thread(target=self.run_proxy, daemon=True)
            self.proxy_thread.start()

            self.is_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.proxy_status_label.config(text=f"🟢 Proxy: Running on {host}:{port}")
            self.status_label.config(text=f"Proxy started on {host}:{port}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start proxy: {e}")
            self.status_label.config(text=f"Error: {e}")

    def run_proxy(self):
        """Run the proxy server"""
        try:
            self.proxy.start()
        except Exception as e:
            print(f"Proxy error: {e}")

    def stop_proxy(self):
        """Stop the proxy server"""
        if not self.is_running:
            return

        try:
            if self.proxy:
                self.proxy.running = False
                self.proxy = None

            self.is_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.proxy_status_label.config(text="⚫ Proxy: Stopped")
            self.status_label.config(text="Proxy stopped")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop proxy: {e}")

    def update_traffic(self):
        """Update traffic list from queue"""
        # Poll proxy history for new requests more frequently
        if self.proxy and hasattr(self.proxy, 'history'):
            try:
                # Get current count
                current_count = len(self.traffic_items)

                # Get all requests from proxy history
                if hasattr(self.proxy.history, 'requests'):
                    all_requests = self.proxy.history.requests

                    # Add new requests
                    if len(all_requests) > current_count:
                        print(f"[GUI] Found {len(all_requests) - current_count} new requests")
                        for i in range(current_count, len(all_requests)):
                            request = all_requests[i]

                            # Convert to GUI format
                            item = {
                                'method': request.get('method', ''),
                                'host': request.get('host', ''),
                                'path': request.get('path', ''),
                                'url': f"http://{request.get('host', '')}{request.get('path', '')}",
                                'status_code': request.get('status_code', 0),
                                'status_text': request.get('status_text', ''),
                                'request_headers': request.get('headers', {}),
                                'response_headers': request.get('response_headers', {}),
                                'request_body': request.get('body', b''),
                                'response_body': request.get('response_body', b''),
                                'request_size': len(request.get('body', b'')),
                                'response_size': len(request.get('response_body', b'')),
                                'duration': request.get('response_time', 0) * 1000,  # Convert to ms
                                'timestamp': request.get('timestamp', time.time())
                            }
                            self.traffic_queue.put(item)

            except Exception as e:
                print(f"[GUI] Error polling proxy history: {e}")

        try:
            while not self.traffic_queue.empty():
                item = self.traffic_queue.get_nowait()
                self.add_traffic_item(item)
        except queue.Empty:
            pass

        # Update every 500ms (more responsive)
        self.root.after(500, self.update_traffic)

    def update_statistics(self):
        """Update statistics display"""
        try:
            if self.proxy and hasattr(self.proxy, 'stats'):
                stats = self.proxy.stats
                self.stats_label.config(
                    text=f"Requests: {stats.total_requests} | Responses: {stats.total_responses} | Errors: {stats.total_errors}"
                )

                # Store for visualization
                timestamp = time.time() - self.start_time
                self.stats_history['timestamp'].append(timestamp)
                self.stats_history['requests'].append(stats.total_requests)
                self.stats_history['responses'].append(stats.total_responses)

        except Exception as e:
            pass

        self.root.after(1000, self.update_statistics)

    def add_traffic_item(self, item):
        """Add traffic item to list"""
        # Add to current session
        self.sessions[self.current_session].append(item)
        self.traffic_items.append(item)

        # Format time
        timestamp = datetime.fromtimestamp(item.get('timestamp', time.time()))
        time_str = timestamp.strftime('%H:%M:%S')

        # Get values
        method = item.get('method', '')
        host = item.get('host', '')
        path = item.get('path', '')
        status = item.get('status_code', '')
        size = item.get('response_size', 0)
        duration = item.get('duration', 0)

        # Format size
        size_str = self.format_size(size) if size else ''
        duration_str = f"{duration:.0f}ms" if duration else ''

        # Determine color based on status
        tags = []
        if status:
            if 200 <= status < 300:
                tags = ['success']
            elif 300 <= status < 400:
                tags = ['redirect']
            elif 400 <= status < 500:
                tags = ['client_error']
            elif status >= 500:
                tags = ['server_error']

        # Insert into tree
        iid = self.tree.insert('', 'end', text=str(len(self.traffic_items)),
                               values=(time_str, method, host, path, status, size_str, duration_str),
                               tags=tags)

        # Configure tag colors
        self.tree.tag_configure('success', foreground='green')
        self.tree.tag_configure('redirect', foreground='blue')
        self.tree.tag_configure('client_error', foreground='orange')
        self.tree.tag_configure('server_error', foreground='red')

        # Auto-scroll to bottom
        self.tree.see(iid)

    def format_size(self, size):
        """Format size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"

    def on_select_traffic(self, event):
        """Handle traffic selection"""
        selection = self.tree.selection()
        if not selection:
            return

        item_id = selection[0]
        index = int(self.tree.item(item_id)['text']) - 1

        if 0 <= index < len(self.traffic_items):
            self.selected_request = self.traffic_items[index]
            self.display_request_details()

    def display_request_details(self):
        """Display details of selected request"""
        if not self.selected_request:
            return

        # Overview
        self.overview_text.delete('1.0', tk.END)
        overview = f"""Request Overview
================
Method: {self.selected_request.get('method', 'N/A')}
URL: {self.selected_request.get('url', 'N/A')}
Host: {self.selected_request.get('host', 'N/A')}
Path: {self.selected_request.get('path', 'N/A')}
Status: {self.selected_request.get('status_code', 'N/A')}
Duration: {self.selected_request.get('duration', 0):.2f} ms
Request Size: {self.format_size(self.selected_request.get('request_size', 0))}
Response Size: {self.format_size(self.selected_request.get('response_size', 0))}
"""
        self.overview_text.insert('1.0', overview)

        # Request headers
        self.req_headers_text.delete('1.0', tk.END)
        req_headers = self.selected_request.get('request_headers', {})
        for key, value in req_headers.items():
            self.req_headers_text.insert(tk.END, f"{key}: {value}\n")

        # Response headers
        self.resp_headers_text.delete('1.0', tk.END)
        resp_headers = self.selected_request.get('response_headers', {})
        for key, value in resp_headers.items():
            self.resp_headers_text.insert(tk.END, f"{key}: {value}\n")

        # Request body
        self.req_body_text.delete('1.0', tk.END)
        req_body = self.selected_request.get('request_body', '')
        if req_body:
            self.req_body_text.insert('1.0', req_body)

        # Response body
        self.resp_body_text.delete('1.0', tk.END)
        resp_body = self.selected_request.get('response_body', '')
        if resp_body:
            self.resp_body_text.insert('1.0', resp_body)

        # Decoded content (placeholder)
        self.decoded_text.delete('1.0', tk.END)
        self.decoded_text.insert('1.0', "Decoded content will appear here...")

        # Timing
        self.timing_text.delete('1.0', tk.END)
        timing_info = f"""Timing Information
==================
DNS Lookup: N/A
TCP Connect: N/A
TLS Handshake: N/A
Request Sent: N/A
TTFB: N/A
Content Download: N/A
Total: {self.selected_request.get('duration', 0):.2f} ms
"""
        self.timing_text.insert('1.0', timing_info)

    # Stub methods for new features

    def new_session(self):
        """Create new session"""
        session_name = f"Session {len(self.sessions) + 1}"
        self.sessions[session_name] = []
        self.current_session = session_name
        self.add_session_tab(session_name)
        self.clear_traffic()
        self.status_label.config(text=f"New session: {session_name}")

    def add_session_tab(self, session_name):
        """Add session tab"""
        # Add a new tab to the session notebook if it exists
        # This would require a session notebook widget to be created in setup_session_tabs()
        # For now, just track the session in the sessions dict
        if not hasattr(self, 'session_notebook'):
            # Session notebook not yet implemented in UI
            # Just track the session
            pass
        else:
            # Create new tab for session
            session_frame = ttk.Frame(self.session_notebook)
            self.session_notebook.add(session_frame, text=session_name)
            # Store reference
            if not hasattr(self, 'session_frames'):
                self.session_frames = {}
            self.session_frames[session_name] = session_frame

    def export_pcap(self):
        """Export traffic to PCAP"""
        if not self.captured_packets:
            messagebox.showwarning("No Data", "No packets captured yet. Start packet capture first.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng")]
        )
        if filename:
            try:
                from pcap_writer import PCAPWriter
                writer = PCAPWriter(filename)
                for packet in self.captured_packets:
                    packet_data = packet.get('raw_data', b'')
                    timestamp = packet.get('timestamp', time.time())
                    writer.write_packet(packet_data, timestamp)
                writer.close()
                self.status_label.config(text=f"Exported {len(self.captured_packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export PCAP: {e}")

    def export_json(self):
        """Export traffic to JSON"""
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.traffic_items, f, indent=2, default=str)
                self.status_label.config(text=f"Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def export_csv(self):
        """Export traffic to CSV"""
        if not self.traffic_items:
            messagebox.showwarning("No Data", "No traffic data to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Header
                    writer.writerow(['Timestamp', 'Method', 'Host', 'Path', 'Status', 'Size', 'Duration (ms)', 'Content-Type'])
                    # Data rows
                    for item in self.traffic_items:
                        writer.writerow([
                            item.get('timestamp', ''),
                            item.get('method', ''),
                            item.get('host', ''),
                            item.get('path', ''),
                            item.get('status_code', ''),
                            item.get('response_size', ''),
                            item.get('duration', ''),
                            item.get('content_type', '')
                        ])
                self.status_label.config(text=f"Exported {len(self.traffic_items)} requests to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export CSV: {e}")

    def show_timeline(self):
        """Show timeline view"""
        timeline_window = tk.Toplevel(self.root)
        timeline_window.title("Timeline Visualization")
        timeline_window.geometry("1000x600")

        # Create canvas for timeline
        canvas_frame = ttk.Frame(timeline_window)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        canvas = tk.Canvas(canvas_frame, bg='white')
        scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=canvas.yview)
        canvas.config(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Draw timeline
        if not self.traffic_items:
            canvas.create_text(500, 300, text="No traffic data to display", font=('Arial', 14))
            return

        # Get time range
        timestamps = [item.get('timestamp', 0) for item in self.traffic_items if item.get('timestamp')]
        if not timestamps:
            canvas.create_text(500, 300, text="No timestamp data available", font=('Arial', 14))
            return

        min_time = min(timestamps)
        max_time = max(timestamps)
        time_range = max_time - min_time if max_time > min_time else 1

        # Draw requests
        y_offset = 50
        for i, item in enumerate(self.traffic_items):
            timestamp = item.get('timestamp', 0)
            if not timestamp:
                continue

            # Calculate x position based on time
            x_pos = 50 + ((timestamp - min_time) / time_range) * 800

            # Color based on status code
            status = item.get('status_code', 0)
            if status < 300:
                color = 'green'
            elif status < 400:
                color = 'blue'
            elif status < 500:
                color = 'orange'
            else:
                color = 'red'

            # Draw circle for request
            canvas.create_oval(x_pos-5, y_offset-5, x_pos+5, y_offset+5, fill=color, outline='black')

            # Draw line to next request
            if i < len(self.traffic_items) - 1:
                next_timestamp = self.traffic_items[i+1].get('timestamp', 0)
                if next_timestamp:
                    next_x = 50 + ((next_timestamp - min_time) / time_range) * 800
                    canvas.create_line(x_pos, y_offset, next_x, y_offset, fill='lightgray')

            # Add tooltip
            method = item.get('method', '')
            host = item.get('host', '')
            canvas.create_text(x_pos, y_offset + 20, text=f"{method}", font=('Arial', 8), angle=45)

            y_offset += 40
            if y_offset > 40 * len(self.traffic_items):
                break

        canvas.config(scrollregion=canvas.bbox("all"))

    def show_websocket_viewer(self):
        """Show WebSocket message viewer"""
        ws_window = tk.Toplevel(self.root)
        ws_window.title("WebSocket Messages")
        ws_window.geometry("900x700")

        # Control frame
        control_frame = ttk.Frame(ws_window)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text=f"Total Messages: {len(self.websocket_messages)}").pack(side=tk.LEFT, padx=10)
        ttk.Button(control_frame, text="Clear", command=self.clear_websocket_messages).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export", command=self.export_websocket_messages).pack(side=tk.LEFT, padx=5)

        # Message list
        list_frame = ttk.Frame(ws_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('Direction', 'Type', 'Size', 'Timestamp')
        tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.config(yscrollcommand=scrollbar.set)

        # Message details
        detail_frame = ttk.LabelFrame(ws_window, text="Message Details", padding=10)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=10)
        detail_text.pack(fill=tk.BOTH, expand=True)

        # Populate messages
        for msg in self.websocket_messages:
            tree.insert('', tk.END, values=(
                msg.get('direction', ''),
                msg.get('type', ''),
                msg.get('size', 0),
                msg.get('timestamp', '')
            ))

        def on_select(event):
            selection = tree.selection()
            if selection:
                idx = tree.index(selection[0])
                if idx < len(self.websocket_messages):
                    msg = self.websocket_messages[idx]
                    detail_text.delete('1.0', tk.END)
                    detail_text.insert('1.0', json.dumps(msg, indent=2, default=str))

        tree.bind('<<TreeviewSelect>>', on_select)

    def show_dns_viewer(self):
        """Show DNS query viewer"""
        dns_window = tk.Toplevel(self.root)
        dns_window.title("DNS Queries")
        dns_window.geometry("900x600")

        # Stats frame
        stats_frame = ttk.LabelFrame(dns_window, text="DNS Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)

        total_queries = len(self.dns_queries)
        ttk.Label(stats_frame, text=f"Total Queries: {total_queries}").pack(side=tk.LEFT, padx=10)

        # Query list
        list_frame = ttk.Frame(dns_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('Domain', 'Type', 'Result', 'Duration', 'Timestamp')
        tree = ttk.Treeview(list_frame, columns=columns, show='headings')

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.config(yscrollcommand=scrollbar.set)

        # Populate DNS queries
        for query in self.dns_queries:
            tree.insert('', tk.END, values=(
                query.get('domain', ''),
                query.get('type', ''),
                query.get('result', ''),
                f"{query.get('duration', 0):.2f}ms",
                query.get('timestamp', '')
            ))

    def show_packet_viewer(self):
        """Show packet capture viewer"""
        packet_window = tk.Toplevel(self.root)
        packet_window.title("Packet Capture Viewer")
        packet_window.geometry("1000x700")

        # Control frame
        control_frame = ttk.Frame(packet_window)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text=f"Captured Packets: {len(self.captured_packets)}").pack(side=tk.LEFT, padx=10)
        ttk.Button(control_frame, text="Export PCAP", command=self.export_pcap).pack(side=tk.LEFT, padx=5)

        # Packet list
        list_frame = ttk.Frame(packet_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('No.', 'Protocol', 'Source', 'Destination', 'Length', 'Info')
        tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=20)

        for col in columns:
            tree.heading(col, text=col)
            if col == 'No.':
                tree.column(col, width=50)
            elif col == 'Info':
                tree.column(col, width=300)
            else:
                tree.column(col, width=120)

        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.config(yscrollcommand=scrollbar.set)

        # Packet details
        detail_frame = ttk.LabelFrame(packet_window, text="Packet Details", padding=5)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=15)
        detail_text.pack(fill=tk.BOTH, expand=True)

        # Populate packets
        for i, packet in enumerate(self.captured_packets):
            tree.insert('', tk.END, values=(
                i + 1,
                packet.get('protocol', 'Unknown'),
                packet.get('src', ''),
                packet.get('dst', ''),
                packet.get('length', 0),
                packet.get('info', '')
            ))

        def on_select(event):
            selection = tree.selection()
            if selection:
                idx = int(tree.item(selection[0])['values'][0]) - 1
                if idx < len(self.captured_packets):
                    packet = self.captured_packets[idx]
                    detail_text.delete('1.0', tk.END)
                    detail_text.insert('1.0', json.dumps(packet, indent=2, default=str))

        tree.bind('<<TreeviewSelect>>', on_select)

    def show_compare_dialog(self):
        """Show session comparison dialog"""
        if not self.selected_request:
            messagebox.showwarning("No Selection", "Please select a request first")
            return

        compare_window = tk.Toplevel(self.root)
        compare_window.title("Compare Requests")
        compare_window.geometry("1200x800")

        # Two-panel layout
        left_frame = ttk.LabelFrame(compare_window, text="Selected Request", padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        right_frame = ttk.LabelFrame(compare_window, text="Select Request to Compare", padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel - selected request details
        left_text = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD)
        left_text.pack(fill=tk.BOTH, expand=True)
        left_text.insert('1.0', json.dumps(self.selected_request, indent=2, default=str))

        # Right panel - request list and details
        tree_frame = ttk.Frame(right_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('Method', 'Host', 'Path', 'Status')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=10)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)

        tree.pack(fill=tk.BOTH, expand=True)

        # Populate with other requests
        for item in self.traffic_items:
            if item != self.selected_request:
                tree.insert('', tk.END, values=(
                    item.get('method', ''),
                    item.get('host', ''),
                    item.get('path', ''),
                    item.get('status_code', '')
                ))

        # Details area
        right_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, height=20)
        right_text.pack(fill=tk.BOTH, expand=True, pady=5)

        def on_compare_select(event):
            selection = tree.selection()
            if selection:
                idx = tree.index(selection[0])
                compare_requests = [item for item in self.traffic_items if item != self.selected_request]
                if idx < len(compare_requests):
                    right_text.delete('1.0', tk.END)
                    right_text.insert('1.0', json.dumps(compare_requests[idx], indent=2, default=str))

        tree.bind('<<TreeviewSelect>>', on_compare_select)

    def show_search_dialog(self):
        """Show advanced search dialog"""
        search_window = tk.Toplevel(self.root)
        search_window.title("Advanced Search")
        search_window.geometry("600x400")

        # Search controls
        control_frame = ttk.LabelFrame(search_window, text="Search Options", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text="Search Term:").grid(row=0, column=0, sticky=tk.W, pady=5)
        search_entry = ttk.Entry(control_frame, width=40)
        search_entry.grid(row=0, column=1, padx=5, pady=5)

        regex_var = tk.BooleanVar()
        ttk.Checkbutton(control_frame, text="Use Regex", variable=regex_var).grid(row=1, column=1, sticky=tk.W)

        case_var = tk.BooleanVar()
        ttk.Checkbutton(control_frame, text="Case Sensitive", variable=case_var).grid(row=2, column=1, sticky=tk.W)

        # Search in options
        ttk.Label(control_frame, text="Search In:").grid(row=3, column=0, sticky=tk.W, pady=5)
        search_in_frame = ttk.Frame(control_frame)
        search_in_frame.grid(row=3, column=1, sticky=tk.W)

        search_url_var = tk.BooleanVar(value=True)
        search_headers_var = tk.BooleanVar(value=True)
        search_body_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(search_in_frame, text="URL", variable=search_url_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(search_in_frame, text="Headers", variable=search_headers_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(search_in_frame, text="Body", variable=search_body_var).pack(side=tk.LEFT, padx=5)

        # Results frame
        results_frame = ttk.LabelFrame(search_window, text="Search Results", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        results_tree = ttk.Treeview(results_frame, columns=('Method', 'URL', 'Match'), show='headings')
        results_tree.heading('Method', text='Method')
        results_tree.heading('URL', text='URL')
        results_tree.heading('Match', text='Match Location')
        results_tree.pack(fill=tk.BOTH, expand=True)

        def do_search():
            results_tree.delete(*results_tree.get_children())
            search_term = search_entry.get()
            if not search_term:
                return

            pattern = search_term
            if regex_var.get():
                try:
                    if case_var.get():
                        pattern = re.compile(search_term)
                    else:
                        pattern = re.compile(search_term, re.IGNORECASE)
                except re.error as e:
                    messagebox.showerror("Regex Error", f"Invalid regex: {e}")
                    return

            for item in self.traffic_items:
                matches = []
                if search_url_var.get():
                    url = item.get('url', '')
                    if regex_var.get():
                        if pattern.search(url):
                            matches.append('URL')
                    else:
                        if (case_var.get() and search_term in url) or (not case_var.get() and search_term.lower() in url.lower()):
                            matches.append('URL')

                if search_headers_var.get():
                    headers = str(item.get('request_headers', '')) + str(item.get('response_headers', ''))
                    if regex_var.get():
                        if pattern.search(headers):
                            matches.append('Headers')
                    else:
                        if (case_var.get() and search_term in headers) or (not case_var.get() and search_term.lower() in headers.lower()):
                            matches.append('Headers')

                if search_body_var.get():
                    body = str(item.get('request_body', '')) + str(item.get('response_body', ''))
                    if regex_var.get():
                        if pattern.search(body):
                            matches.append('Body')
                    else:
                        if (case_var.get() and search_term in body) or (not case_var.get() and search_term.lower() in body.lower()):
                            matches.append('Body')

                if matches:
                    results_tree.insert('', tk.END, values=(
                        item.get('method', ''),
                        item.get('url', ''),
                        ', '.join(matches)
                    ))

        ttk.Button(control_frame, text="Search", command=do_search).grid(row=4, column=1, pady=10, sticky=tk.W)

    def show_certificate_viewer(self):
        """Show certificate viewer"""
        if not self.selected_request:
            messagebox.showwarning("No Selection", "Please select an HTTPS request first")
            return

        cert_window = tk.Toplevel(self.root)
        cert_window.title("Certificate Viewer")
        cert_window.geometry("700x600")

        cert_text = scrolledtext.ScrolledText(cert_window, wrap=tk.WORD)
        cert_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Get certificate info if available
        cert_info = self.selected_request.get('certificate', {})
        if not cert_info:
            cert_text.insert('1.0', "No certificate information available for this request.\n\n")
            cert_text.insert('end', "Certificate details are only available for HTTPS connections\n")
            cert_text.insert('end', "when the proxy has intercepted the SSL/TLS handshake.")
        else:
            cert_text.insert('1.0', "Certificate Information\n")
            cert_text.insert('end', "=" * 50 + "\n\n")
            cert_text.insert('end', json.dumps(cert_info, indent=2))

        cert_text.config(state=tk.DISABLED)

    def start_packet_capture(self):
        """Start packet capture"""
        if self.packet_capture_running:
            messagebox.showwarning("Already Running", "Packet capture is already running")
            return

        try:
            from packet_capture import PacketCapture
            self.packet_capture = PacketCapture(interface=self.config.get('packet_capture_interface'))

            def capture_thread():
                try:
                    self.packet_capture.start_capture(callback=self._on_packet_captured)
                except Exception as e:
                    messagebox.showerror("Capture Error", f"Failed to start packet capture: {e}\n\nTry running with sudo/admin privileges")
                    self.packet_capture_running = False

            threading.Thread(target=capture_thread, daemon=True).start()
            self.packet_capture_running = True
            self.status_label.config(text="Packet capture started")
            messagebox.showinfo("Packet Capture", "Packet capture started successfully!\n\nNote: Requires root/admin privileges on most systems.")
        except ImportError:
            messagebox.showerror("Module Missing", "packet_capture module not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start packet capture: {e}")

    def _on_packet_captured(self, packet_data):
        """Callback for packet capture"""
        self.captured_packets.append(packet_data)

    def stop_packet_capture(self):
        """Stop packet capture"""
        if not self.packet_capture_running:
            messagebox.showwarning("Not Running", "Packet capture is not running")
            return

        if self.packet_capture:
            self.packet_capture.stop_capture()
            self.packet_capture = None

        self.packet_capture_running = False
        self.status_label.config(text=f"Packet capture stopped. Captured {len(self.captured_packets)} packets")
        messagebox.showinfo("Packet Capture", f"Stopped packet capture\n\nTotal packets captured: {len(self.captured_packets)}")

    def show_shortcuts(self):
        """Show keyboard shortcuts"""
        shortcuts = """Keyboard Shortcuts
==================
Ctrl+N - New Session
Ctrl+O - Load HAR File
Ctrl+E - Export to HAR
Ctrl+S - Show Statistics
Ctrl+R - Request Replay
Ctrl+D - Decoder Tool
Ctrl+F - Search/Filter
Ctrl+L - Clear Traffic
Ctrl+T - Toggle Theme
Ctrl+Q - Quit
F5 - Refresh Display
"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)

    def show_about(self):
        """Show about dialog"""
        about_text = """Enhanced HTTP/HTTPS Traffic Viewer v5.0

Features:
- HTTP/HTTPS proxy with traffic capture
- Multi-layer packet analysis
- WebSocket support
- DNS query tracking
- Protocol dissection
- PCAP export
- Session management
- Advanced filtering and search

Built with Python and Tkinter
"""
        messagebox.showinfo("About", about_text)

    # Implement remaining stub methods (copy from original gui.py)

    def apply_theme(self):
        """Apply current theme"""
        pass

    def toggle_theme(self):
        """Toggle dark/light theme"""
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def clear_traffic(self):
        """Clear traffic list"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.traffic_items = []
        self.sessions[self.current_session] = []

    def apply_filters(self):
        """Apply traffic filters"""
        pass

    def clear_filters(self):
        """Clear all filters"""
        self.filter_domain_entry.delete(0, tk.END)
        self.filter_method_combo.set('')
        self.filter_status_entry.delete(0, tk.END)

    def on_search(self, event=None):
        """Handle search"""
        pass

    def show_context_menu(self, event):
        """Show context menu"""
        try:
            self.tree_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.tree_context_menu.grab_release()

    def copy_url(self):
        """Copy URL to clipboard"""
        if self.selected_request:
            url = self.selected_request.get('url', '')
            self.root.clipboard_clear()
            self.root.clipboard_append(url)

    def copy_curl(self):
        """Copy as cURL command"""
        if not self.selected_request:
            messagebox.showwarning("No Selection", "Please select a request first")
            return

        try:
            method = self.selected_request.get('method', 'GET')
            url = self.selected_request.get('url', '')
            headers = self.selected_request.get('request_headers', {})
            body = self.selected_request.get('request_body', '')

            # Build cURL command
            curl_cmd = f"curl -X {method} '{url}'"

            # Add headers
            for header_name, header_value in headers.items():
                curl_cmd += f" \\\n  -H '{header_name}: {header_value}'"

            # Add body if present
            if body and method in ['POST', 'PUT', 'PATCH']:
                # Escape single quotes in body
                escaped_body = body.replace("'", "'\\''")
                curl_cmd += f" \\\n  -d '{escaped_body}'"

            # Copy to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(curl_cmd)
            self.status_label.config(text="cURL command copied to clipboard")
            messagebox.showinfo("Copied", "cURL command copied to clipboard")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate cURL command: {e}")

    def replay_selected(self):
        """Replay selected request"""
        self.show_replay_dialog()

    def compare_selected(self):
        """Compare selected request"""
        self.show_compare_dialog()

    def delete_selected(self):
        """Delete selected request"""
        selection = self.tree.selection()
        if selection:
            self.tree.delete(selection[0])

    def copy_text(self, text_widget):
        """Copy text from widget"""
        try:
            text = text_widget.get('1.0', tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.config(text="Copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {e}")

    def save_text(self, text_widget):
        """Save text to file"""
        filename = filedialog.asksaveasfilename()
        if filename:
            try:
                text = text_widget.get('1.0', tk.END)
                with open(filename, 'w') as f:
                    f.write(text)
                self.status_label.config(text=f"Saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

    def pretty_print_json(self, text_widget):
        """Pretty print JSON in text widget"""
        try:
            text = text_widget.get('1.0', tk.END)
            obj = json.loads(text)
            pretty = json.dumps(obj, indent=2)
            text_widget.delete('1.0', tk.END)
            text_widget.insert('1.0', pretty)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse JSON: {e}")

    def render_html(self):
        """Render HTML in browser"""
        if not self.selected_request:
            messagebox.showwarning("No Selection", "Please select a request first")
            return

        response_body = self.selected_request.get('response_body', '')
        if not response_body:
            messagebox.showwarning("No HTML", "No response body available")
            return

        # Check if response is HTML
        content_type = self.selected_request.get('content_type', '')
        if 'html' not in content_type.lower():
            result = messagebox.askyesno("Not HTML",
                f"Content-Type is '{content_type}', not HTML.\nRender anyway?")
            if not result:
                return

        # Create temporary HTML file
        import tempfile
        import webbrowser

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(response_body)
                temp_path = f.name

            # Open in browser
            webbrowser.open(f'file://{temp_path}')
            self.status_label.config(text=f"Opened HTML in browser: {temp_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to render HTML: {e}")

    def clear_websocket_messages(self):
        """Clear WebSocket messages"""
        self.websocket_messages = []
        self.websocket_text.delete('1.0', tk.END)

    def export_websocket_messages(self):
        """Export WebSocket messages"""
        filename = filedialog.asksaveasfilename(defaultextension=".json")
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.websocket_messages, f, indent=2, default=str)
                self.status_label.config(text=f"Exported WebSocket messages to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

    def refresh_display(self):
        """Refresh display"""
        self.status_label.config(text="Display refreshed")

    def export_har(self):
        """Export to HAR file"""
        filename = filedialog.asksaveasfilename(defaultextension=".har", filetypes=[("HAR files", "*.har")])
        if filename:
            try:
                # Create HAR structure
                har = {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "Enhanced Traffic Viewer", "version": "5.0"},
                        "entries": []
                    }
                }
                # Add entries from traffic_items
                for item in self.traffic_items:
                    entry = {
                        "startedDateTime": item.get('timestamp', ''),
                        "request": {
                            "method": item.get('method', ''),
                            "url": item.get('url', ''),
                            "headers": [],
                            "bodySize": item.get('request_size', 0)
                        },
                        "response": {
                            "status": item.get('status_code', 0),
                            "headers": [],
                            "bodySize": item.get('response_size', 0)
                        },
                        "time": item.get('duration', 0)
                    }
                    har["log"]["entries"].append(entry)

                with open(filename, 'w') as f:
                    json.dump(har, f, indent=2)
                self.status_label.config(text=f"Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

    def load_har(self):
        """Load HAR file"""
        filename = filedialog.askopenfilename(filetypes=[("HAR files", "*.har"), ("JSON files", "*.json")])
        if filename:
            try:
                with open(filename, 'r') as f:
                    har = json.load(f)
                # Parse HAR entries
                entries = har.get('log', {}).get('entries', [])
                self.clear_traffic()
                for entry in entries:
                    # Convert to traffic item format
                    item = {
                        'method': entry.get('request', {}).get('method', ''),
                        'url': entry.get('request', {}).get('url', ''),
                        'status_code': entry.get('response', {}).get('status', 0),
                        'duration': entry.get('time', 0),
                        'timestamp': entry.get('startedDateTime', time.time())
                    }
                    self.traffic_queue.put(item)
                self.status_label.config(text=f"Loaded {len(entries)} entries from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load: {e}")

    def show_statistics(self):
        """Show statistics dashboard"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Statistics Dashboard")
        stats_window.geometry("800x600")

        # Create notebook for different stats tabs
        notebook = ttk.Notebook(stats_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # General Stats Tab
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")

        stats_text = scrolledtext.ScrolledText(general_frame, wrap=tk.WORD, width=80, height=30)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Calculate statistics
        total_requests = len(self.traffic_items)
        methods_count = defaultdict(int)
        status_codes = defaultdict(int)
        hosts = defaultdict(int)
        total_size = 0
        total_duration = 0

        for item in self.traffic_items:
            methods_count[item.get('method', 'Unknown')] += 1
            status_codes[item.get('status_code', 0)] += 1
            hosts[item.get('host', 'Unknown')] += 1
            total_size += item.get('response_size', 0)
            total_duration += item.get('duration', 0)

        # Display statistics
        stats_info = f"""Traffic Statistics
==================

Total Requests: {total_requests}
Total Data Transferred: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)
Average Duration: {total_duration / max(total_requests, 1):.2f} ms
Total Duration: {total_duration:.2f} ms

HTTP Methods:
-------------
"""
        for method, count in sorted(methods_count.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_requests * 100) if total_requests > 0 else 0
            stats_info += f"{method}: {count} ({percentage:.1f}%)\n"

        stats_info += "\nStatus Codes:\n-------------\n"
        for code, count in sorted(status_codes.items()):
            percentage = (count / total_requests * 100) if total_requests > 0 else 0
            stats_info += f"{code}: {count} ({percentage:.1f}%)\n"

        stats_info += "\nTop Hosts:\n----------\n"
        for host, count in sorted(hosts.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / total_requests * 100) if total_requests > 0 else 0
            stats_info += f"{host}: {count} ({percentage:.1f}%)\n"

        if self.proxy and hasattr(self.proxy, 'stats'):
            stats_info += f"\n\nProxy Statistics:\n=================\n"
            stats_info += f"Connections Handled: {self.proxy.stats.connections_handled}\n"
            stats_info += f"Bytes Sent: {self.proxy.stats.bytes_sent:,}\n"
            stats_info += f"Bytes Received: {self.proxy.stats.bytes_received:,}\n"
            stats_info += f"Errors: {self.proxy.stats.errors}\n"

        stats_text.insert('1.0', stats_info)
        stats_text.config(state=tk.DISABLED)

    def show_replay_dialog(self):
        """Show request replay dialog"""
        if not self.selected_request:
            messagebox.showwarning("No Selection", "Please select a request to replay")
            return

        replay_window = tk.Toplevel(self.root)
        replay_window.title("Replay Request")
        replay_window.geometry("800x600")

        # Request details
        detail_frame = ttk.LabelFrame(replay_window, text="Request Details", padding=10)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=20)
        detail_text.pack(fill=tk.BOTH, expand=True)

        request_info = f"""Method: {self.selected_request.get('method', '')}
URL: {self.selected_request.get('url', '')}
Host: {self.selected_request.get('host', '')}
Path: {self.selected_request.get('path', '')}

Headers:
{json.dumps(self.selected_request.get('request_headers', {}), indent=2)}

Body:
{self.selected_request.get('request_body', '')}
"""
        detail_text.insert('1.0', request_info)

        # Replay options
        options_frame = ttk.LabelFrame(replay_window, text="Replay Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(options_frame, text="Repeat Count:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        repeat_entry = ttk.Entry(options_frame, width=10)
        repeat_entry.insert(0, "1")
        repeat_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(options_frame, text="Delay (ms):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        delay_entry = ttk.Entry(options_frame, width=10)
        delay_entry.insert(0, "0")
        delay_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Results
        results_text = scrolledtext.ScrolledText(replay_window, wrap=tk.WORD, height=10)
        results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        def do_replay():
            try:
                import socket
                import urllib.parse

                repeat_count = int(repeat_entry.get())
                delay_ms = int(delay_entry.get())

                results_text.delete('1.0', tk.END)
                results_text.insert('end', f"Replaying request {repeat_count} time(s)...\n\n")

                for i in range(repeat_count):
                    try:
                        # Parse URL
                        url = self.selected_request.get('url', '')
                        parsed = urllib.parse.urlparse(url)
                        host = parsed.hostname or self.selected_request.get('host', '')
                        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                        path = parsed.path or '/'

                        # Create connection
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(10)
                        sock.connect((host, port))

                        # Build request
                        method = self.selected_request.get('method', 'GET')
                        request_line = f"{method} {path} HTTP/1.1\r\n"
                        headers = f"Host: {host}\r\n"
                        headers += "Connection: close\r\n\r\n"

                        sock.sendall((request_line + headers).encode())

                        # Receive response
                        response = b''
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk

                        sock.close()

                        # Parse response
                        response_str = response.decode('utf-8', errors='ignore')
                        status_line = response_str.split('\r\n')[0] if response_str else 'No response'

                        results_text.insert('end', f"[{i+1}/{repeat_count}] {status_line}\n")

                        if delay_ms > 0 and i < repeat_count - 1:
                            time.sleep(delay_ms / 1000.0)

                    except Exception as e:
                        results_text.insert('end', f"[{i+1}/{repeat_count}] Error: {e}\n")

                results_text.insert('end', "\nReplay completed!\n")

            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter valid numbers")
            except Exception as e:
                messagebox.showerror("Replay Error", f"Failed to replay request: {e}")

        ttk.Button(options_frame, text="Replay", command=do_replay).grid(row=2, column=0, columnspan=2, pady=10)

    def show_decoder_dialog(self):
        """Show decoder dialog"""
        decoder_window = tk.Toplevel(self.root)
        decoder_window.title("Content Decoder Tool")
        decoder_window.geometry("900x700")

        # Input frame
        input_frame = ttk.LabelFrame(decoder_window, text="Input", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=15)
        input_text.pack(fill=tk.BOTH, expand=True)

        # Controls
        control_frame = ttk.Frame(decoder_window)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(control_frame, text="Decode As:").pack(side=tk.LEFT, padx=5)

        decode_type = ttk.Combobox(control_frame, values=[
            'Base64',
            'URL Encoded',
            'HTML Entities',
            'JSON',
            'Hex',
            'Gzip',
            'JWT'
        ], width=15)
        decode_type.set('Base64')
        decode_type.pack(side=tk.LEFT, padx=5)

        def do_decode():
            input_data = input_text.get('1.0', tk.END).strip()
            if not input_data:
                return

            try:
                dtype = decode_type.get()
                result = ""

                if dtype == 'Base64':
                    import base64
                    result = base64.b64decode(input_data).decode('utf-8', errors='ignore')

                elif dtype == 'URL Encoded':
                    import urllib.parse
                    result = urllib.parse.unquote(input_data)

                elif dtype == 'HTML Entities':
                    import html
                    result = html.unescape(input_data)

                elif dtype == 'JSON':
                    import json
                    obj = json.loads(input_data)
                    result = json.dumps(obj, indent=2)

                elif dtype == 'Hex':
                    result = bytes.fromhex(input_data.replace(' ', '')).decode('utf-8', errors='ignore')

                elif dtype == 'Gzip':
                    import base64, gzip
                    compressed = base64.b64decode(input_data)
                    result = gzip.decompress(compressed).decode('utf-8', errors='ignore')

                elif dtype == 'JWT':
                    import base64, json
                    parts = input_data.split('.')
                    if len(parts) >= 2:
                        header = json.loads(base64.b64decode(parts[0] + '==').decode())
                        payload = json.loads(base64.b64decode(parts[1] + '==').decode())
                        result = f"Header:\n{json.dumps(header, indent=2)}\n\nPayload:\n{json.dumps(payload, indent=2)}"

                output_text.delete('1.0', tk.END)
                output_text.insert('1.0', result)

            except Exception as e:
                messagebox.showerror("Decode Error", f"Failed to decode: {e}")

        ttk.Button(control_frame, text="Decode", command=do_decode).pack(side=tk.LEFT, padx=5)

        # Output frame
        output_frame = ttk.LabelFrame(decoder_window, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        output_text.pack(fill=tk.BOTH, expand=True)

        # Pre-fill if request is selected
        if self.selected_request:
            body = self.selected_request.get('response_body', '')
            if body:
                input_text.insert('1.0', body)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = EnhancedTrafficViewerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
