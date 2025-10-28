#!/usr/bin/env python3
"""
Diagnostic Script - Find Simple Issues
Checks for common problems that would prevent GUI from working
"""

import sys
import os

def check_imports():
    """Check if all required modules can be imported"""
    print("="*60)
    print("CHECKING IMPORTS")
    print("="*60)

    errors = []

    try:
        import tkinter
        print("✅ tkinter: OK")
    except ImportError as e:
        print(f"❌ tkinter: MISSING - {e}")
        errors.append("tkinter")

    try:
        from http_https_viewer import HTTPSViewer
        print("✅ http_https_viewer: OK")
    except ImportError as e:
        print(f"❌ http_https_viewer: MISSING - {e}")
        errors.append("http_https_viewer")

    try:
        from decoders import ContentDecoder
        print("✅ decoders: OK")
    except ImportError as e:
        print(f"⚠️  decoders: MISSING (optional) - {e}")

    return errors

def check_files():
    """Check if all required files exist"""
    print("\n" + "="*60)
    print("CHECKING FILES")
    print("="*60)

    required_files = [
        'http_https_viewer.py',
        'fixed_gui.py',
        'enhanced_gui.py',
        'test_http_server.py'
    ]

    errors = []
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file}: EXISTS")
        else:
            print(f"❌ {file}: MISSING")
            errors.append(file)

    return errors

def check_syntax():
    """Check Python syntax of key files"""
    print("\n" + "="*60)
    print("CHECKING SYNTAX")
    print("="*60)

    import py_compile

    files_to_check = ['fixed_gui.py', 'enhanced_gui.py', 'http_https_viewer.py']
    errors = []

    for file in files_to_check:
        if os.path.exists(file):
            try:
                py_compile.compile(file, doraise=True)
                print(f"✅ {file}: SYNTAX OK")
            except py_compile.PyCompileError as e:
                print(f"❌ {file}: SYNTAX ERROR")
                print(f"   {e}")
                errors.append(file)
        else:
            print(f"⚠️  {file}: NOT FOUND")

    return errors

def check_port_availability():
    """Check if ports are available"""
    print("\n" + "="*60)
    print("CHECKING PORT AVAILABILITY")
    print("="*60)

    import socket

    ports_to_check = {
        8000: "Test HTTP Server",
        9000: "Proxy Server"
    }

    available = {}

    for port, name in ports_to_check.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.bind(('127.0.0.1', port))
            sock.close()
            print(f"✅ Port {port} ({name}): AVAILABLE")
            available[port] = True
        except OSError:
            print(f"❌ Port {port} ({name}): IN USE")
            available[port] = False

    return available

def test_proxy_basic():
    """Test if proxy can be instantiated"""
    print("\n" + "="*60)
    print("TESTING PROXY INSTANTIATION")
    print("="*60)

    try:
        from http_https_viewer import HTTPSViewer

        # Try to create proxy (don't start it)
        proxy = HTTPSViewer(host='127.0.0.1', port=9999)  # Use unusual port

        # Check if it has required attributes
        checks = {
            'history': hasattr(proxy, 'history'),
            'stats': hasattr(proxy, 'stats'),
            'history.requests': hasattr(proxy.history, 'requests') if hasattr(proxy, 'history') else False
        }

        for attr, exists in checks.items():
            if exists:
                print(f"✅ proxy.{attr}: EXISTS")
            else:
                print(f"❌ proxy.{attr}: MISSING")

        return all(checks.values())

    except Exception as e:
        print(f"❌ Error creating proxy: {e}")
        return False

def test_gui_imports():
    """Test if GUI can import what it needs"""
    print("\n" + "="*60)
    print("TESTING GUI IMPORTS")
    print("="*60)

    try:
        # Simulate what GUI does
        import tkinter as tk
        from tkinter import ttk
        import queue
        import threading
        from http_https_viewer import HTTPSViewer

        print("✅ All GUI imports: OK")
        return True
    except Exception as e:
        print(f"❌ GUI import error: {e}")
        return False

def check_history_structure():
    """Test history structure"""
    print("\n" + "="*60)
    print("TESTING HISTORY STRUCTURE")
    print("="*60)

    try:
        from http_https_viewer import HTTPSViewer

        proxy = HTTPSViewer(host='127.0.0.1', port=9999)

        print(f"✅ proxy.history type: {type(proxy.history)}")
        print(f"✅ proxy.history.requests type: {type(proxy.history.requests)}")
        print(f"✅ Current requests count: {len(proxy.history.requests)}")

        # Try adding a fake request
        test_request = {
            'method': 'GET',
            'host': 'test.com',
            'path': '/test',
            'status_code': 200
        }

        proxy.history.add(test_request)
        print(f"✅ After adding test request: {len(proxy.history.requests)} requests")

        if len(proxy.history.requests) == 1:
            print("✅ History add/retrieve: WORKING")
            return True
        else:
            print("❌ History add/retrieve: NOT WORKING")
            return False

    except Exception as e:
        print(f"❌ Error testing history: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*15 + "DIAGNOSTIC SCRIPT" + " "*26 + "║")
    print("║" + " "*10 + "Finding Simple Overlooked Issues" + " "*15 + "║")
    print("╚" + "="*58 + "╝")
    print()

    # Run all checks
    results = {}

    results['imports'] = len(check_imports()) == 0
    results['files'] = len(check_files()) == 0
    results['syntax'] = len(check_syntax()) == 0
    results['ports'] = check_port_availability()
    results['proxy'] = test_proxy_basic()
    results['gui_imports'] = test_gui_imports()
    results['history'] = check_history_structure()

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    all_good = all([
        results['imports'],
        results['files'],
        results['syntax'],
        results['proxy'],
        results['gui_imports'],
        results['history']
    ])

    if all_good:
        print("✅ ALL CHECKS PASSED!")
        print("\nYour setup is correct. If GUI still doesn't show traffic:")
        print("1. Make sure you're testing with HTTP (not HTTPS)")
        print("2. Start test server: python3 test_http_server.py")
        print("3. Start GUI: python3 fixed_gui.py")
        print("4. Configure browser to use proxy 127.0.0.1:9000")
        print("5. Visit: http://127.0.0.1:8000/test")
        print("\nYou should see:")
        print("  Terminal: [GUI] Found 1 new requests")
        print("  GUI: Request in traffic list")
    else:
        print("❌ SOME CHECKS FAILED!")
        print("\nFix the issues above before proceeding.")

    print("\n" + "="*60)
    print("PORT ARCHITECTURE EXPLANATION")
    print("="*60)
    print("""
Port 8000: Test HTTP Server (the TARGET you're testing)
Port 9000: Proxy Server (the MIDDLEMAN that captures traffic)

Flow:
  Browser (configured to use proxy 9000)
     ↓
  Proxy (9000) ← Captures and displays traffic here!
     ↓
  Test Server (8000) ← The destination

When you visit http://127.0.0.1:8000 in your browser:
  1. Browser sends request to Proxy (9000)
  2. Proxy captures the request (adds to history)
  3. Proxy forwards to Test Server (8000)
  4. Test Server responds
  5. Proxy captures response
  6. Proxy forwards response to Browser
  7. GUI shows captured request/response!

This is CORRECT and NORMAL proxy behavior!
""")

if __name__ == '__main__':
    main()
