#!/usr/bin/env python3
"""
Example client script to test the HTTP/HTTPS viewer proxy
"""

import requests
import sys

def test_http_proxy(proxy_url='http://127.0.0.1:8888'):
    """Test HTTP requests through the proxy"""

    proxies = {
        'http': proxy_url,
        'https': proxy_url,
    }

    print("Testing HTTP/HTTPS Proxy Viewer\n")
    print("=" * 60)

    # Test 1: Simple HTTP GET
    print("\n1. Testing HTTP GET request...")
    try:
        response = requests.get('http://httpbin.org/get', proxies=proxies, timeout=10)
        print(f"   ✓ Status: {response.status_code}")
    except Exception as e:
        print(f"   ✗ Error: {e}")

    # Test 2: HTTP POST
    print("\n2. Testing HTTP POST request...")
    try:
        data = {'key': 'value', 'test': 'data'}
        response = requests.post('http://httpbin.org/post', json=data, proxies=proxies, timeout=10)
        print(f"   ✓ Status: {response.status_code}")
    except Exception as e:
        print(f"   ✗ Error: {e}")

    # Test 3: HTTPS GET
    print("\n3. Testing HTTPS GET request...")
    try:
        response = requests.get('https://httpbin.org/get', proxies=proxies, timeout=10)
        print(f"   ✓ Status: {response.status_code}")
    except Exception as e:
        print(f"   ✗ Error: {e}")

    # Test 4: Custom headers
    print("\n4. Testing request with custom headers...")
    try:
        headers = {
            'User-Agent': 'TestClient/1.0',
            'X-Custom-Header': 'CustomValue'
        }
        response = requests.get('http://httpbin.org/headers', headers=headers, proxies=proxies, timeout=10)
        print(f"   ✓ Status: {response.status_code}")
    except Exception as e:
        print(f"   ✗ Error: {e}")

    print("\n" + "=" * 60)
    print("Testing complete! Check the proxy output for traffic details.")

if __name__ == '__main__':
    proxy = 'http://127.0.0.1:8888'

    if len(sys.argv) > 1:
        proxy = sys.argv[1]

    print(f"Using proxy: {proxy}")
    print("Make sure the proxy server is running first!")
    print("Start it with: python http_https_viewer.py\n")

    try:
        test_http_proxy(proxy)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
