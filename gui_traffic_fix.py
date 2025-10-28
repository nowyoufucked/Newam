"""
Quick Fix for Enhanced GUI Traffic Display
Add this method to enhanced_gui.py and call it from update_traffic
"""

def poll_proxy_history(self):
    """Poll proxy history for new traffic items"""
    if not self.proxy or not hasattr(self.proxy, 'history'):
        return

    try:
        # Get all requests from proxy history
        if hasattr(self.proxy.history, 'requests'):
            proxy_requests = self.proxy.history.requests

            # Check if we have new requests
            current_count = len(self.traffic_items)
            proxy_count = len(proxy_requests)

            if proxy_count > current_count:
                # Add new requests to GUI
                for i in range(current_count, proxy_count):
                    request = proxy_requests[i]
                    # Convert to GUI format
                    item = {
                        'method': request.get('method', ''),
                        'host': request.get('host', ''),
                        'path': request.get('path', ''),
                        'url': request.get('url', ''),
                        'status_code': request.get('status_code', 0),
                        'status_text': request.get('status_text', ''),
                        'request_headers': request.get('request_headers', {}),
                        'response_headers': request.get('response_headers', {}),
                        'request_body': request.get('request_body', ''),
                        'response_body': request.get('response_body', ''),
                        'request_size': request.get('request_size', 0),
                        'response_size': request.get('response_size', 0),
                        'duration': request.get('response_time', 0) * 1000,  # Convert to ms
                        'timestamp': request.get('timestamp', time.time())
                    }
                    self.traffic_queue.put(item)
    except Exception as e:
        print(f"Error polling proxy history: {e}")

# Then modify update_traffic to call this:
def update_traffic(self):
    """Update traffic list from queue"""
    # Poll proxy history first
    self.poll_proxy_history()

    try:
        while not self.traffic_queue.empty():
            item = self.traffic_queue.get_nowait()
            self.add_traffic_item(item)
    except queue.Empty:
        pass

    self.root.after(100, self.update_traffic)
