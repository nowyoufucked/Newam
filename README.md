# HTTP/HTTPS Traffic Viewer

A Python-based proxy server for monitoring and viewing HTTP and HTTPS traffic from targeted applications.

## ⚠️ Important Security Warning

**This tool is intended for DEFENSIVE SECURITY and DEVELOPMENT purposes only.**

- ✅ Use on applications you own or develop
- ✅ Use for debugging and testing your own software
- ✅ Use for security research on systems you have permission to test
- ❌ DO NOT use to intercept traffic without authorization
- ❌ DO NOT use to capture credentials or sensitive data from others
- ❌ Unauthorized interception of network traffic may be illegal in your jurisdiction

## Features

- 🔍 View HTTP requests and responses in real-time
- 🔒 Support for HTTPS traffic via CONNECT tunneling
- 📊 Colored terminal output for easy reading
- 💾 Optional logging to file
- 🎯 Configurable host and port
- 🔧 Verbose mode for detailed inspection

## Requirements

- Python 3.6 or higher
- No external dependencies for basic functionality
- Optional: `cryptography` package for SSL certificate generation

## Installation

1. Clone or download this repository
2. (Optional) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Start the proxy on default host (127.0.0.1) and port (8888):

```bash
python http_https_viewer.py
```

### Configure Your Application

Set your application to use the proxy:

**Environment Variables:**
```bash
export HTTP_PROXY=http://127.0.0.1:8888
export HTTPS_PROXY=http://127.0.0.1:8888
```

**For Python requests:**
```python
import requests

proxies = {
    'http': 'http://127.0.0.1:8888',
    'https': 'http://127.0.0.1:8888',
}

response = requests.get('http://example.com', proxies=proxies)
```

**For curl:**
```bash
curl -x http://127.0.0.1:8888 http://example.com
```

**For browsers:**
Configure proxy settings in your browser's network preferences to use `127.0.0.1:8888`.

### Command Line Options

```bash
python http_https_viewer.py [options]
```

Options:
- `-H, --host HOST` - Host to bind to (default: 127.0.0.1)
- `-p, --port PORT` - Port to listen on (default: 8888)
- `-v, --verbose` - Verbose mode (show all headers and details)
- `-o, --output FILE` - Save traffic to file
- `-h, --help` - Show help message

### Examples

**Listen on a different port:**
```bash
python http_https_viewer.py -p 9000
```

**Verbose mode with all headers:**
```bash
python http_https_viewer.py -v
```

**Save traffic to a log file:**
```bash
python http_https_viewer.py -o traffic.log
```

**Combine options:**
```bash
python http_https_viewer.py -p 9000 -v -o traffic.log
```

## SSL Certificate Generation (Optional)

For advanced HTTPS interception (not required for basic tunneling):

```bash
python cert_generator.py
```

This will generate:
- `proxy_key.pem` - Private key
- `proxy_cert.pem` - Self-signed certificate

To trust the certificate on your system:

**Linux:**
```bash
sudo cp proxy_cert.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy_cert.pem
```

**Windows:**
```bash
certutil -addstore -f "ROOT" proxy_cert.pem
```

## How It Works

### HTTP Traffic
1. Client sends HTTP request to proxy
2. Proxy parses and displays the request
3. Proxy forwards request to target server
4. Proxy receives response from server
5. Proxy displays response and forwards it to client

### HTTPS Traffic (CONNECT Tunneling)
1. Client sends CONNECT request to proxy
2. Proxy establishes connection to target server
3. Proxy sends "Connection Established" to client
4. Proxy relays encrypted data between client and server
5. Traffic remains encrypted (end-to-end)

## Output Format

The proxy displays traffic with color-coded output:

- **Purple**: Request/Response headers
- **Blue**: Request details (method, path, version)
- **Cyan**: Header information
- **Green**: Response status and server responses
- **Yellow**: Connection information
- **Red**: Errors

Example output:
```
[2025-10-28 12:34:56] [Connection #1] HTTP request from 127.0.0.1:54321
================================================================================
HTTP REQUEST
--------------------------------------------------------------------------------
GET /api/users HTTP/1.1
  Host: api.example.com
  User-Agent: MyApp/1.0
  Content-Type: application/json
HTTP RESPONSE: HTTP/1.1 200 OK
================================================================================
```

## Testing

Test with curl:
```bash
# Terminal 1: Start the proxy
python http_https_viewer.py

# Terminal 2: Make a request through the proxy
curl -x http://127.0.0.1:8888 http://httpbin.org/get
curl -x http://127.0.0.1:8888 https://httpbin.org/get
```

Test with Python:
```python
import requests

proxies = {
    'http': 'http://127.0.0.1:8888',
    'https': 'http://127.0.0.1:8888',
}

# HTTP request
response = requests.get('http://httpbin.org/get', proxies=proxies)
print(response.status_code)

# HTTPS request
response = requests.get('https://httpbin.org/get', proxies=proxies)
print(response.status_code)
```

## Troubleshooting

### Connection Refused
- Ensure the proxy is running
- Check that you're using the correct host and port
- Verify firewall settings aren't blocking the port

### SSL Certificate Errors
- For HTTPS tunneling, no certificate installation is needed
- For full HTTPS decryption, ensure certificates are properly installed
- Some applications may not trust self-signed certificates

### No Traffic Visible
- Verify your application is configured to use the proxy
- Check that the application supports proxy settings
- Try verbose mode (`-v`) for more details

## Limitations

- HTTPS traffic is tunneled (encrypted), so request/response bodies cannot be seen without certificate installation
- Some applications may bypass system proxy settings
- WebSocket connections are not fully supported
- Very large requests/responses may consume significant memory

## Security Considerations

- Only run this proxy on localhost (127.0.0.1) unless you have a specific need
- Do not expose this proxy to the internet
- Be careful when installing root certificates - they can be a security risk
- Traffic logs may contain sensitive information - handle them securely
- Always delete certificates after testing

## License

This project is provided as-is for educational and development purposes.

## Contributing

This tool is designed for defensive security and development. Contributions that enhance security analysis capabilities are welcome, but any features that could be used maliciously will not be accepted.

## Disclaimer

The authors are not responsible for any misuse of this tool. Users are responsible for ensuring they have proper authorization before monitoring any network traffic. Always comply with applicable laws and regulations.
