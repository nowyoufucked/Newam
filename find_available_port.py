#!/usr/bin/env python3
"""
Find Available Port for Windows
Quickly finds an available port for the proxy to use
"""

import socket

def is_port_available(port, host='127.0.0.1'):
    """Check if a port is available"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.bind((host, port))
        sock.close()
        return True
    except (socket.error, OSError) as e:
        return False

def find_available_port(start_port=8888, max_attempts=100):
    """Find the first available port starting from start_port"""
    common_ports = [9000, 8080, 8889, 3128, 8090, 9090, 7000, 5000, 4000]

    # Try common ports first
    for port in common_ports:
        if is_port_available(port):
            return port

    # Then try sequential ports
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port

    return None

def main():
    print("=" * 60)
    print("Port Availability Checker for HTTP/HTTPS Viewer")
    print("=" * 60)
    print()

    # Check default port
    default_port = 8888
    print(f"Checking default port {default_port}...", end=" ")
    if is_port_available(default_port):
        print(f"✓ Available")
        print(f"\nYou can use: python3 http_https_viewer.py -p {default_port}")
        return
    else:
        print("✗ In use or blocked")

    print("\nSearching for available port...")
    available_port = find_available_port()

    if available_port:
        print(f"\n✓ Found available port: {available_port}")
        print(f"\nTo start the proxy:")
        print(f"  Command line: python3 http_https_viewer.py -p {available_port} -v -b")
        print(f"  Enhanced GUI: python3 enhanced_gui.py")
        print(f"                (Then set port to {available_port} in the GUI)")
        print(f"  Basic GUI:    python3 gui.py")
        print(f"                (Then set port to {available_port} in the GUI)")
    else:
        print("\n✗ Could not find any available port!")
        print("\nPossible solutions:")
        print("1. Close other applications that might be using ports")
        print("2. Run as Administrator")
        print("3. Check Windows Firewall settings")
        print("4. Try running: netstat -ano | findstr :8888")
        print("   to see what's using port 8888")

    print("\n" + "=" * 60)
    input("Press Enter to exit...")

if __name__ == '__main__':
    main()
