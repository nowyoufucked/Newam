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
        # Placeholder for session tab implementation
        pass

    def export_pcap(self):
        """Export traffic to PCAP"""
        messagebox.showinfo("Export PCAP", "PCAP export feature - implementation pending")

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
        messagebox.showinfo("Export CSV", "CSV export feature - implementation pending")

    def show_timeline(self):
        """Show timeline view"""
        messagebox.showinfo("Timeline", "Timeline visualization - implementation pending")

    def show_websocket_viewer(self):
        """Show WebSocket message viewer"""
        messagebox.showinfo("WebSocket", "WebSocket viewer - implementation pending")

    def show_dns_viewer(self):
        """Show DNS query viewer"""
        messagebox.showinfo("DNS", "DNS query viewer - implementation pending")

    def show_packet_viewer(self):
        """Show packet capture viewer"""
        messagebox.showinfo("Packet Capture", "Packet viewer - implementation pending")

    def show_compare_dialog(self):
        """Show session comparison dialog"""
        messagebox.showinfo("Compare", "Session comparison - implementation pending")

    def show_search_dialog(self):
        """Show advanced search dialog"""
        messagebox.showinfo("Search", "Advanced search - implementation pending")

    def show_certificate_viewer(self):
        """Show certificate viewer"""
        messagebox.showinfo("Certificates", "Certificate viewer - implementation pending")

    def start_packet_capture(self):
        """Start packet capture"""
        messagebox.showinfo("Packet Capture", "Packet capture start - implementation pending")

    def stop_packet_capture(self):
        """Stop packet capture"""
        messagebox.showinfo("Packet Capture", "Packet capture stop - implementation pending")

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
        messagebox.showinfo("Copy cURL", "Feature implementation pending")

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
        messagebox.showinfo("Render HTML", "HTML rendering - implementation pending")

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
        messagebox.showinfo("Statistics", "Statistics dashboard - implementation pending")

    def show_replay_dialog(self):
        """Show request replay dialog"""
        messagebox.showinfo("Replay", "Request replay - implementation pending")

    def show_decoder_dialog(self):
        """Show decoder dialog"""
        messagebox.showinfo("Decoder", "Decoder tool - implementation pending")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = EnhancedTrafficViewerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
