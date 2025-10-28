#!/usr/bin/env python3
"""
Fixed Enhanced GUI - Working Traffic Display
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import json
from datetime import datetime
import time
import sys
import os

# Import proxy modules
try:
    from http_https_viewer import HTTPSViewer, RequestHistory, Statistics
    from decoders import ContentDecoder
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)


class GUIHTTPSViewer(HTTPSViewer):
    """Custom proxy that sends traffic to GUI queue"""

    def __init__(self, *args, gui_queue=None, **kwargs):
        self.gui_queue = gui_queue
        super().__init__(*args, **kwargs)

    def log(self, message, color=None):
        """Override log to also send to GUI"""
        super().log(message, color)

        # Send to GUI queue if this is a request
        if self.gui_queue and "→" in message:
            # This is a request/response log
            # We'll get the actual data from history
            pass


class FixedEnhancedGUI:
    """Fixed Enhanced GUI with working traffic display"""

    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced HTTP/HTTPS Traffic Viewer - FIXED")
        self.root.geometry("1400x900")

        # State
        self.proxy = None
        self.proxy_thread = None
        self.is_running = False
        self.traffic_queue = queue.Queue()
        self.traffic_items = []
        self.selected_request = None
        self.last_history_check = 0

        # Configuration
        self.config = {
            'host': '127.0.0.1',
            'port': 9000,  # Default to 9000 for Windows
            'verbose': True,
            'show_body': True,
        }

        self.setup_ui()

        # Start update loops
        self.update_traffic()
        self.root.after(2000, self.show_instructions)

    def setup_ui(self):
        """Setup minimal but working UI"""

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

        ttk.Label(control_frame, text="Status:").pack(side=tk.LEFT, padx=10)
        self.status_label = ttk.Label(control_frame, text="⚫ Stopped", foreground="red")
        self.status_label.pack(side=tk.LEFT)

        # Traffic list
        list_frame = ttk.LabelFrame(self.root, text="Traffic (Updates every 500ms)", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview
        tree_scroll = ttk.Scrollbar(list_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(list_frame,
                                 columns=('Method', 'Host', 'Path', 'Status', 'Size', 'Time'),
                                 show='tree headings',
                                 yscrollcommand=tree_scroll.set)
        tree_scroll.config(command=self.tree.yview)

        self.tree.column('#0', width=50)
        self.tree.column('Method', width=80)
        self.tree.column('Host', width=200)
        self.tree.column('Path', width=300)
        self.tree.column('Status', width=80)
        self.tree.column('Size', width=100)
        self.tree.column('Time', width=100)

        self.tree.heading('#0', text='#')
        self.tree.heading('Method', text='Method')
        self.tree.heading('Host', text='Host')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Time', text='Time')

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        # Details panel
        details_frame = ttk.LabelFrame(self.root, text="Details", padding=5)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=15)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def show_instructions(self):
        """Show usage instructions"""
        instructions = """
        INSTRUCTIONS:
        1. Click "Start Proxy" above
        2. Configure your browser to use proxy: 127.0.0.1:9000
        3. Browse any website (try: http://httpbin.org/get)
        4. Traffic will appear below!

        Troubleshooting:
        - If port 9000 is blocked, try changing to 8080, 5000, or 3000
        - Make sure your browser is using the proxy
        - Check the terminal for detailed proxy logs
        """
        self.details_text.insert('1.0', instructions)

    def start_proxy(self):
        """Start the proxy server"""
        if self.is_running:
            messagebox.showwarning("Already Running", "Proxy is already running")
            return

        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())

            # Create custom proxy with GUI queue
            self.proxy = GUIHTTPSViewer(
                host=host,
                port=port,
                verbose=True,
                show_body=True,
                gui_queue=self.traffic_queue
            )

            # Start proxy in thread
            self.proxy_thread = threading.Thread(target=self.proxy.start, daemon=True)
            self.proxy_thread.start()

            self.is_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text=f"🟢 Running on {host}:{port}", foreground="green")
            self.status_bar.config(text=f"Proxy started on {host}:{port} - Configure your browser to use this proxy")

            messagebox.showinfo("Proxy Started",
                               f"Proxy is running on {host}:{port}\n\n"
                               f"Configure your browser:\n"
                               f"HTTP Proxy: {host}\n"
                               f"Port: {port}\n\n"
                               f"Then browse any website to see traffic!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start proxy: {e}\n\nTry a different port (8080, 5000, 3000)")
            self.status_bar.config(text=f"Error: {e}")

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
            self.status_label.config(text="⚫ Stopped", foreground="red")
            self.status_bar.config(text="Proxy stopped")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop proxy: {e}")

    def update_traffic(self):
        """Update traffic list from proxy history"""
        # Debug: First call
        if not hasattr(self, '_update_traffic_called'):
            self._update_traffic_called = True
            print("[GUI] update_traffic() is running - will check every 500ms")

        if self.proxy and hasattr(self.proxy, 'history'):
            try:
                # Get current count
                current_count = len(self.traffic_items)

                # Get all requests from proxy history
                if hasattr(self.proxy.history, 'requests'):
                    all_requests = self.proxy.history.requests

                    # Debug: Show history size periodically
                    if not hasattr(self, '_last_check_count'):
                        self._last_check_count = 0

                    # Only print every 10th check to reduce spam
                    self._last_check_count += 1
                    if self._last_check_count % 10 == 0:
                        print(f"[GUI DEBUG] Checking history... Current: {current_count}, History: {len(all_requests)}")

                    # Add new requests
                    if len(all_requests) > current_count:
                        new_count = len(all_requests) - current_count
                        print(f"[GUI] ✅ Found {new_count} new requests (total: {len(all_requests)})")

                        for i in range(current_count, len(all_requests)):
                            request = all_requests[i]
                            print(f"[GUI] Adding request #{i+1}: {request.get('method', '?')} {request.get('host', '?')}{request.get('path', '?')}")
                            self.add_traffic_item(request)

                        # Update status bar
                        self.status_bar.config(text=f"Captured {len(all_requests)} requests")
                else:
                    if not hasattr(self, '_warned_no_requests_attr'):
                        self._warned_no_requests_attr = True
                        print("[GUI WARNING] proxy.history exists but has no 'requests' attribute")

            except Exception as e:
                print(f"[GUI ERROR] Error updating traffic: {e}")
                import traceback
                traceback.print_exc()
        else:
            # Proxy not running yet
            if not hasattr(self, '_warned_no_proxy'):
                if self.is_running:  # Only warn if proxy should be running
                    self._warned_no_proxy = True
                    print("[GUI WARNING] Proxy is running but proxy.history not accessible")

        # Schedule next update (every 500ms)
        self.root.after(500, self.update_traffic)

    def add_traffic_item(self, request):
        """Add request to traffic list"""
        self.traffic_items.append(request)
        idx = len(self.traffic_items)

        # Extract values
        method = request.get('method', '')
        host = request.get('host', '')
        path = request.get('path', '')
        status = request.get('status_code', 0)
        size = len(request.get('response_body', b''))
        response_time = request.get('response_time', 0)

        # Format size
        if size < 1024:
            size_str = f"{size}B"
        elif size < 1024*1024:
            size_str = f"{size/1024:.1f}KB"
        else:
            size_str = f"{size/(1024*1024):.1f}MB"

        # Format time
        time_str = f"{response_time*1000:.0f}ms"

        # Determine color
        if status < 300:
            tag = 'success'
        elif status < 400:
            tag = 'redirect'
        elif status < 500:
            tag = 'error'
        else:
            tag = 'server_error'

        # Insert into tree
        self.tree.insert('', 'end', text=str(idx),
                        values=(method, host, path, status, size_str, time_str),
                        tags=(tag,))

        # Configure tag colors
        self.tree.tag_configure('success', foreground='green')
        self.tree.tag_configure('redirect', foreground='blue')
        self.tree.tag_configure('error', foreground='orange')
        self.tree.tag_configure('server_error', foreground='red')

        # Auto-scroll
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

    def on_select(self, event):
        """Handle selection"""
        selection = self.tree.selection()
        if not selection:
            return

        item_id = selection[0]
        idx = int(self.tree.item(item_id)['text']) - 1

        if 0 <= idx < len(self.traffic_items):
            request = self.traffic_items[idx]
            self.display_details(request)

    def display_details(self, request):
        """Display request details"""
        self.details_text.delete('1.0', tk.END)

        details = f"""
=== REQUEST ===
Method: {request.get('method', '')}
Host: {request.get('host', '')}
Path: {request.get('path', '')}
Version: {request.get('version', '')}

Headers:
{self.format_headers(request.get('headers', {}))}

Body:
{self.format_body(request.get('body', b''))}

=== RESPONSE ===
Status: {request.get('status_code', 0)} {request.get('status_text', '')}
Time: {request.get('response_time', 0)*1000:.2f}ms

Headers:
{self.format_headers(request.get('response_headers', {}))}

Body:
{self.format_body(request.get('response_body', b''))}
"""

        self.details_text.insert('1.0', details)

    def format_headers(self, headers):
        """Format headers dict"""
        if not headers:
            return "(none)"
        return '\n'.join(f"{k}: {v}" for k, v in headers.items())

    def format_body(self, body):
        """Format body"""
        if not body:
            return "(empty)"

        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8')
            except:
                return f"(binary data - {len(body)} bytes)"

        # Try to pretty print JSON
        try:
            obj = json.loads(body)
            return json.dumps(obj, indent=2)
        except:
            # Return first 1000 chars
            if len(body) > 1000:
                return body[:1000] + f"\n\n... ({len(body)-1000} more characters)"
            return body


def main():
    print("="*60)
    print("Enhanced HTTP/HTTPS Traffic Viewer - FIXED VERSION")
    print("="*60)
    print()
    print("Starting GUI...")
    print()
    print("IMPORTANT:")
    print("1. The GUI will open")
    print("2. Click 'Start Proxy'")
    print("3. Configure your browser to use proxy 127.0.0.1:9000")
    print("4. Browse any website")
    print("5. Traffic will appear in the GUI!")
    print()
    print("Troubleshooting:")
    print("- If you see 'Port already in use', change the port in the GUI")
    print("- Check this terminal window for detailed proxy logs")
    print("- Make sure your browser is configured to use the proxy")
    print()
    print("="*60)

    root = tk.Tk()
    app = FixedEnhancedGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
