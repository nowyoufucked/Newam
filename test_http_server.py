#!/usr/bin/env python3
"""
Simple HTTP Test Server
Creates a local HTTP server to test the proxy with plain HTTP traffic
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime

class TestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        response = {
            'method': 'GET',
            'path': self.path,
            'timestamp': datetime.now().isoformat(),
            'headers': dict(self.headers),
            'message': 'This is a test response from the HTTP test server'
        }

        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        try:
            body_data = json.loads(body.decode())
        except:
            body_data = body.decode()

        response = {
            'method': 'POST',
            'path': self.path,
            'timestamp': datetime.now().isoformat(),
            'headers': dict(self.headers),
            'body': body_data,
            'message': 'POST request received successfully'
        }

        self.wfile.write(json.dumps(response, indent=2).encode())

    def log_message(self, format, *args):
        """Custom log format"""
        print(f"[TEST SERVER] {self.address_string()} - {format%args}")


def main():
    port = 8000
    server = HTTPServer(('127.0.0.1', port), TestHandler)

    print("="*60)
    print("HTTP Test Server for Proxy Testing")
    print("="*60)
    print(f"\nServer running on: http://127.0.0.1:{port}")
    print("\nTest URLs:")
    print(f"  http://127.0.0.1:{port}/")
    print(f"  http://127.0.0.1:{port}/test")
    print(f"  http://127.0.0.1:{port}/api/data")
    print("\nInstructions:")
    print("1. Keep this server running")
    print("2. Start your proxy GUI")
    print("3. Configure browser to use proxy 127.0.0.1:9000")
    print("4. Visit the URLs above in your browser")
    print("5. Watch the proxy GUI - requests will appear!")
    print("\nPress Ctrl+C to stop")
    print("="*60)
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[+] Server stopped")
        server.shutdown()


if __name__ == '__main__':
    main()
