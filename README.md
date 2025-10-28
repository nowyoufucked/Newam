# HTTP/HTTPS Traffic Viewer - Enhanced Edition

A powerful Python-based proxy server for monitoring, analyzing, and replaying HTTP and HTTPS traffic from targeted applications.
**Now with GUI!** 🎨

## ⚠️ Important Security Warning

**This tool is intended for DEFENSIVE SECURITY and DEVELOPMENT purposes only.**

- ✅ Use on applications you own or develop
- ✅ Use for debugging and testing your own software
- ✅ Use for security research on systems you have permission to test
- ❌ DO NOT use to intercept traffic without authorization
- ❌ DO NOT use to capture credentials or sensitive data from others
- ❌ Unauthorized interception of network traffic may be illegal in your jurisdiction

## Quick Start

### GUI (Recommended for most users)

**Basic GUI:**
```bash
# Linux/macOS
./launch_gui.sh

# Windows
launch_gui.bat

# Or directly
python3 gui.py
```

**Enhanced GUI (with all advanced features):**
```bash
# Directly
python3 enhanced_gui.py

# Note: Some features (packet capture) require root/admin privileges
sudo python3 enhanced_gui.py  # Linux/macOS with packet capture
```

### Command Line
```bash
python3 http_https_viewer.py -v -b
```

### Packet Capture (requires root/admin)
```bash
# Capture 100 packets and save to PCAP
sudo python3 packet_capture.py -c 100 -v -o capture.pcap

# Open in Wireshark
wireshark capture.pcap
```

## Features

### 🖥️ Graphical User Interface
**Basic GUI (gui.py)**:
- **Modern tkinter interface** - Clean, intuitive design
- **Live traffic monitoring** - Real-time updates as traffic flows
- **Request/Response viewer** - Detailed inspection with tabs
- **Automatic decoding** - Visual display of decoded content
- **Interactive filtering** - Filter by domain, method, status
- **Statistics dashboard** - Real-time metrics and charts
- **HAR export/import** - Save and load traffic sessions
- **Request replay** - Replay requests with modifications
- **Built-in decoder tools** - Quick JWT, Base64, URL decoding
- **Dark/Light themes** - Comfortable viewing in any lighting
- **Cross-platform** - Works on Windows, macOS, Linux

**Enhanced GUI (enhanced_gui.py - NEW v5.0)**:
- ⭐ **All Basic GUI Features** - Everything from gui.py
- 📁 **Session Management** - Multiple sessions with tabs
- 🌐 **WebSocket Viewer** - Dedicated tab for WebSocket messages
- 🔍 **DNS Query Viewer** - Monitor and analyze DNS queries
- 📦 **Packet Details Tab** - View packet headers (Ethernet/IP/TCP/UDP)
- 🔎 **Regex Search** - Advanced search with regular expressions
- 📊 **Timeline View** - Visualize requests on timeline
- 🔄 **Session Comparison** - Compare traffic between sessions
- 📤 **Multiple Export Formats** - HAR, PCAP, JSON, CSV
- ⌨️ **Keyboard Shortcuts** - 10+ shortcuts for efficiency
- 📋 **Context Menu** - Right-click for quick actions
- 🔐 **Certificate Viewer** - View TLS certificate details
- ⏱️ **Timing Tab** - Detailed request timing breakdown
- 🎯 **Enhanced Filtering** - Multi-field filters with regex

**See [GUI_ENHANCEMENTS.md](GUI_ENHANCEMENTS.md) for comprehensive GUI documentation.**

### Core Proxy Features
- 🔍 Real-time HTTP/HTTPS traffic monitoring
- 🔒 HTTPS CONNECT tunneling support
- 📊 Color-coded terminal output
- 💾 Optional logging to file
- 🎯 Configurable host and port
- 🔧 Verbose mode for detailed inspection

### Enhanced Features (v2.0)
- ✨ **Request/Response Body Viewing** - See the actual data being transmitted
- 🎨 **JSON Pretty Printing** - Automatic formatting of JSON payloads
- 🔎 **Advanced Filtering** - Filter by domain, HTTP method, or status code
- 📈 **Statistics Tracking** - Request counts, response times, data transfer metrics
- 📝 **Request History** - Store up to 1000 requests in memory
- 💿 **HAR Export** - Export captured traffic to HAR format
- 🔄 **Request Replay** - Replay captured requests for testing
- 📊 **Traffic Analysis** - Comprehensive analysis of captured traffic
- ⚡ **Response Time Tracking** - Monitor performance with millisecond precision
- 🗜️ **Content Decoding** - Automatic decompression of gzip/deflate/brotli

### Advanced Decoding Features (v3.0)
- 🔓 **JWT Token Decoding** - Automatically decode and parse JWT tokens in Authorization headers
- 🔑 **Basic Auth Decoding** - Decode Base64 encoded credentials
- 🍪 **Cookie Parsing** - Parse and display cookie attributes
- 📝 **Form Data Parsing** - Decode URL-encoded and multipart form data
- 🌐 **HTML/XML Formatting** - Pretty print HTML and XML responses
- 🔢 **Hex Dump Viewer** - View binary data in hex format
- 🔤 **Character Encoding** - Auto-detect and convert character encodings
- 📦 **Base64 Decoding** - Decode Base64 content
- 🔗 **URL Decoding** - Decode percent-encoded URLs

### Advanced Capture Features (v4.0 - NEW!)
- 🌐 **WebSocket Support** - Full bidirectional WebSocket traffic capture and monitoring
- 🖥️ **System Proxy Auto-Config** - Automatically configure system-wide proxy settings
- 🔗 **Upstream Proxy Support** - Chain through corporate or other proxy servers
- 🌍 **DNS Resolution Tracking** - Monitor and cache DNS lookups with timing
- ⚡ **Connection Pooling** - Reuse connections for improved performance (HTTP keep-alive)
- 📦 **Chunked Transfer Encoding** - Handle streaming and large file transfers
- 🎯 **Traffic Capture Modes** - Promiscuous, selective, stealth, and debug modes
- 🔄 **Redirect Chain Tracking** - Track complete HTTP redirect flows
- 📊 **Advanced Statistics** - WebSocket counts, DNS metrics, connection reuse rates

**See [ADVANCED.md](ADVANCED.md) for comprehensive documentation on advanced features.**

### Multi-Layer Packet Analysis (v5.0 - NEW!)
- 📦 **Raw Packet Capture** - Capture packets at kernel level using raw sockets
- 🔬 **Multi-Layer Decoding** - Parse Ethernet, IP, TCP/UDP, and application protocols
- 🌐 **Protocol Dissection** - Deep inspection of HTTP, DNS, ICMP, ARP, and more
- 💾 **PCAP/PCAPNG Export** - Save captures in standard format for Wireshark
- 📊 **Layer-by-Layer Analysis** - Decode all OSI layers from Ethernet to Application
- 🎯 **Promiscuous Mode** - Capture all network traffic on interface (requires root)
- 🔍 **Protocol Identification** - Auto-detect protocols at all layers
- 📈 **Real-Time Statistics** - Protocol distribution, bandwidth per IP, packet rates

**Supported Protocols:**
- **Layer 2:** Ethernet II, ARP
- **Layer 3:** IPv4, IPv6, ICMP
- **Layer 4:** TCP (with flags), UDP
- **Layer 7:** HTTP, HTTPS, DNS, FTP, SSH, SMTP, and 20+ more

**See [PACKET_ANALYSIS.md](PACKET_ANALYSIS.md) for comprehensive packet capture and analysis documentation.**

## Tools Included

1. **enhanced_gui.py** - Advanced GUI with packet capture, WebSocket, DNS, session management (NEW!)
2. **gui.py** - Basic graphical user interface
3. **enhanced_proxy.py** - Advanced proxy with WebSocket, DNS tracking, and more
4. **packet_capture.py** - Raw packet capture at all network layers
5. **protocol_dissectors.py** - Multi-layer protocol parsers (Ethernet/IP/TCP/UDP/HTTP/DNS)
6. **pcap_writer.py** - PCAP/PCAPNG file format reader/writer
7. **http_https_viewer.py** - Main proxy server with enhanced features
8. **request_replay.py** - Replay requests from HAR files
9. **traffic_analyzer.py** - Analyze captured traffic and generate reports
10. **decoders.py** - Standalone decoder utility for various formats
11. **advanced_capture.py** - Advanced traffic capture modules
12. **cert_generator.py** - Generate SSL certificates (optional)
13. **example_client.py** - Test client for proxy validation

## Requirements

- Python 3.6 or higher
- tkinter (for GUI - usually included with Python)
- No external dependencies for basic proxy functionality
- Optional: `requests` library for request replay utility
- Optional: `cryptography` package for SSL certificate generation

## Installation

1. Clone or download this repository
2. (Optional) Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Graphical User Interface (GUI)

The GUI provides the easiest way to use the traffic viewer with all features accessible through a modern interface.

#### Launching the GUI

**Linux/macOS:**
```bash
./launch_gui.sh
# Or directly:
python3 gui.py
```

**Windows:**
```batch
launch_gui.bat
REM Or directly:
python gui.py
```

#### GUI Features

- **Proxy Control Panel**: Start/stop proxy, configure host and port
- **Live Traffic List**: Real-time traffic updates with color-coding
  - Green: Success (2xx)
  - Blue: Redirect (3xx)
  - Orange: Client errors (4xx)
  - Red: Server errors (5xx)
- **Request/Response Viewer**: Tabbed interface showing:
  - Overview: Summary of request/response
  - Headers: All request and response headers
  - Request Body: Formatted request content
  - Response Body: Formatted response content (auto JSON pretty print)
  - Decoded: Automatically decoded JWT, cookies, form data
- **Filtering**: Filter by domain, HTTP method, or status code
- **Statistics**: View comprehensive traffic statistics
- **HAR Export/Import**: Save and load traffic sessions
- **Request Replay**: Replay captured requests with modifications
- **Decoder Tools**: Quick decode JWT, Base64, URL encoding, etc.
- **Theme Toggle**: Switch between light and dark themes

#### Quick GUI Workflow

```
1. Launch GUI (./launch_gui.sh or launch_gui.bat)
2. Configure Host/Port (default 127.0.0.1:8888 works for most cases)
3. Click "Start Proxy"
4. Configure your application to use the proxy
5. Watch requests appear in real-time
6. Click any request to see full details
7. Use "Decoded" tab to see parsed JWT, cookies, etc.
8. Export to HAR when done for analysis
```

For comprehensive GUI documentation, see [GUI.md](GUI.md).

### Enhanced Proxy with Advanced Capture (NEW!)

The enhanced proxy includes all features from the basic proxy plus advanced capabilities to ensure no traffic is missed.

#### Quick Start

```bash
# Start with all advanced features
./enhanced_proxy.py --port 8888 --enable-websocket

# With system-wide proxy configuration
./enhanced_proxy.py --port 8888 --enable-system-proxy

# With upstream corporate proxy
./enhanced_proxy.py --port 8888 --upstream-proxy http://proxy.company.com:8080

# Debug mode for troubleshooting
./enhanced_proxy.py --port 8888 --capture-mode debug
```

#### Key Features

- **WebSocket Support**: Captures real-time bidirectional WebSocket traffic
- **System Proxy Auto-Config**: Automatically configures OS proxy settings (Windows/macOS/Linux)
- **Upstream Proxy Chaining**: Works through corporate or other proxy servers
- **DNS Tracking**: Monitors and caches all DNS resolutions with timing
- **Connection Pooling**: Reuses connections for better performance
- **Chunked Encoding**: Handles streaming and large file transfers
- **Multiple Capture Modes**: Choose from promiscuous, selective, stealth, or debug modes

#### Examples

**Capture WebSocket traffic:**
```bash
./enhanced_proxy.py --port 8888 --enable-websocket
```

**System-wide traffic capture:**
```bash
# Requires admin/root privileges
sudo ./enhanced_proxy.py --enable-system-proxy
```

**Corporate network setup:**
```bash
./enhanced_proxy.py --upstream-proxy http://user:pass@proxy.corp.com:3128
```

**Selective capture (specific domains):**
```python
from enhanced_proxy import EnhancedHTTPSViewer

viewer = EnhancedHTTPSViewer(port=8888, capture_mode='selective')
viewer.capture_mode.set_filter(
    domains=['api.example.com', 'auth.example.com'],
    methods=['POST', 'PUT', 'DELETE']
)
viewer.start()
```

**Full documentation**: See [ADVANCED.md](ADVANCED.md) for comprehensive advanced features documentation including troubleshooting, API reference, and integration examples.

### Main Proxy Server (Command Line)

#### Basic Usage

Start the proxy on default host (127.0.0.1) and port (8888):

```bash
python http_https_viewer.py
```

#### Command Line Options

```bash
python http_https_viewer.py [options]
```

**Options:**
- `-H, --host HOST` - Host to bind to (default: 127.0.0.1)
- `-p, --port PORT` - Port to listen on (default: 8888)
- `-v, --verbose` - Verbose mode (show all headers and details)
- `-b, --show-body` - Display request/response bodies
- `-o, --output FILE` - Save traffic to file
- `--filter-domain DOMAIN` - Only show traffic for matching domain
- `--filter-method METHOD` - Only show specific HTTP methods (GET, POST, etc.)
- `--filter-status CODE` - Only show specific status codes
- `--pretty-json` - Pretty print JSON bodies (default: enabled)
- `--max-body-size BYTES` - Maximum body size to display (default: 10000)

#### Examples

**Basic proxy:**
```bash
python http_https_viewer.py
```

**Verbose mode with body inspection:**
```bash
python http_https_viewer.py -v -b
```

**Filter only API traffic:**
```bash
python http_https_viewer.py --filter-domain api.example.com
```

**Show only POST requests:**
```bash
python http_https_viewer.py --filter-method POST
```

**Find all 404 errors:**
```bash
python http_https_viewer.py --filter-status 404
```

**Full inspection with logging:**
```bash
python http_https_viewer.py -v -b -o traffic.log
```

**Monitor specific domain with body viewing:**
```bash
python http_https_viewer.py --filter-domain api.myapp.com -b
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

**For Node.js:**
```javascript
const axios = require('axios');

axios.get('http://example.com', {
  proxy: {
    host: '127.0.0.1',
    port: 8888
  }
});
```

**For browsers:**
Configure proxy settings in your browser's network preferences to use `127.0.0.1:8888`.

### Request Replay Tool

Replay captured requests for testing and debugging:

```bash
python request_replay.py traffic.har
```

**Options:**
- `-v, --verbose` - Show full request/response details
- `--delay SECONDS` - Delay between requests
- `--modify-host HOST` - Change target host (e.g., localhost:8080)
- `--filter-method METHOD` - Only replay specific methods
- `--limit N` - Limit number of requests to replay

**Examples:**

```bash
# Replay all requests
python request_replay.py traffic.har

# Replay with verbose output
python request_replay.py traffic.har -v

# Replay to different host (testing)
python request_replay.py traffic.har --modify-host localhost:3000

# Replay only POST requests
python request_replay.py traffic.har --filter-method POST

# Replay first 10 requests with 1 second delay
python request_replay.py traffic.har --limit 10 --delay 1
```

### Traffic Analyzer

Analyze captured traffic and generate comprehensive reports:

```bash
python traffic_analyzer.py traffic.har
```

**Features:**
- HTTP method distribution
- Status code analysis
- Response time statistics (min, max, average)
- Data transfer metrics
- Top domains and endpoints
- Slow request detection
- Error identification (4xx, 5xx)
- Content type distribution

**Options:**
- `--slow-threshold MS` - Threshold for slow requests (default: 1000ms)
- `--json` - Output analysis in JSON format

**Example Output:**
```
================================================================================
TRAFFIC ANALYSIS REPORT
================================================================================
File: traffic.har
Total Entries: 150

HTTP METHODS
  GET       :   120 (80.0%)
  POST      :    25 (16.7%)
  PUT       :     5 (3.3%)

STATUS CODES
  200:   130 (86.7%)
  404:    15 (10.0%)
  500:     5 (3.3%)

RESPONSE TIMES
  Min:          45.23 ms
  Max:        2345.67 ms
  Average:     234.56 ms

TOP DOMAINS
  api.example.com                : 85 requests
  cdn.example.com                : 40 requests
  static.example.com             : 25 requests
```

## Statistics Dashboard

When you stop the proxy (Ctrl+C), you'll see comprehensive statistics:

```
PROXY STATISTICS
================================================================================
Uptime: 0:15:32
Total Requests: 245
Total Responses: 243
Bytes Sent: 125,432 (122.49 KB)
Bytes Received: 1,234,567 (1,205.63 KB)

Response Times:
  Average: 156.23 ms
  Min: 12.45 ms
  Max: 2,345.67 ms

Requests by Method:
  GET: 189
  POST: 45
  PUT: 8
  DELETE: 3

Status Codes:
  200: 215
  201: 12
  404: 15
  500: 1

Top Domains:
  api.example.com: 145 requests
  cdn.example.com: 67 requests
  static.example.com: 33 requests
```

## HAR Export

After stopping the proxy, you can export captured traffic to HAR format:

```
Export history to HAR file? (y/n): y
Enter filename (default: traffic.har): my_capture.har
Exported to my_capture.har
```

HAR files can be:
- Opened in browser DevTools
- Analyzed with traffic_analyzer.py
- Replayed with request_replay.py
- Shared with team members
- Imported into other tools

## Decoder Utility

The standalone decoder tool can quickly decode various formats:

```bash
python decoders.py [options]
```

**Supported Decodings:**

```bash
# Decode Base64
python decoders.py --base64 "SGVsbG8gV29ybGQh"
# Output: Hello World!

# Decode JWT Token
python decoders.py --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM..."
# Shows: Header, Payload with decoded timestamps, Signature

# URL Decode
python decoders.py --url "Hello%20World%21%20How%20are%20you%3F"
# Output: Hello World! How are you?

# Parse Cookies
python decoders.py --cookies "session=abc123; user=john; theme=dark"
# Shows parsed cookie names and values

# Parse Form Data
python decoders.py --form "username=john&email=john%40example.com&age=30"
# Shows decoded form fields

# Convert Hex to Text
python decoders.py --hex "48656c6c6f20576f726c64"
# Output: Hello World
```

**Use Cases:**
- Quick JWT token inspection
- Decode authentication headers
- Parse cookie strings
- Debug form submissions
- Convert between encodings

See [DECODING.md](DECODING.md) for comprehensive documentation on all decoding features.

## SSL Certificate Generation (Optional)

For advanced HTTPS interception (not required for basic tunneling):

```bash
python cert_generator.py
```

This generates:
- `proxy_key.pem` - Private key
- `proxy_cert.pem` - Self-signed certificate

**Trust the certificate:**

**Linux:**
```bash
sudo cp proxy_cert.pem /usr/local/share/ca-certificates/proxy_cert.crt
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

## Testing

Test the proxy with the included client:

```bash
# Terminal 1: Start the proxy
python http_https_viewer.py -v

# Terminal 2: Run test client
python example_client.py
```

Test with curl:
```bash
# Terminal 1: Start proxy
python http_https_viewer.py

# Terminal 2: Make requests
curl -x http://127.0.0.1:8888 http://httpbin.org/get
curl -x http://127.0.0.1:8888 https://httpbin.org/get
curl -x http://127.0.0.1:8888 -X POST -d '{"test":"data"}' http://httpbin.org/post
```

## Use Cases

### 1. API Development and Debugging
```bash
# Monitor all API calls during development
python http_https_viewer.py --filter-domain api.myapp.com -v -b -o api_debug.log
```

### 2. Performance Testing
```bash
# Find slow endpoints
python http_https_viewer.py -v
# After capturing, analyze
python traffic_analyzer.py traffic.har
```

### 3. Security Testing
```bash
# Monitor authentication flows
python http_https_viewer.py --filter-method POST -b
```

### 4. Integration Testing
```bash
# Capture production-like traffic
python http_https_viewer.py -o prod_traffic.log
# Replay against staging
python request_replay.py traffic.har --modify-host staging.myapp.com
```

### 5. Error Investigation
```bash
# Filter for errors only
python http_https_viewer.py --filter-status 500 -v -b
```

## Output Format

The proxy displays traffic with color-coded output:

- **Purple**: Request/Response section headers
- **Blue**: Request method, path, and HTTP version
- **Cyan**: Header information
- **Green**: 2xx successful responses
- **Yellow**: Connection info and 3xx redirects
- **Orange**: 4xx client errors
- **Red**: 5xx server errors and critical errors
- **Gray**: Request/response body content

## Advanced Features

### Content Decompression

Automatically decompresses:
- gzip
- deflate
- brotli (if brotli module installed)

### JSON Formatting

Automatically detects and pretty-prints JSON:
- Based on Content-Type header
- Heuristic detection for JSON-like content
- Configurable with `--pretty-json`

### Request History

- Stores last 1000 requests in memory
- Searchable and filterable
- Exportable to HAR format
- Thread-safe implementation

### Statistics Tracking

Real-time tracking of:
- Total requests and responses
- Bytes sent and received
- Response time statistics
- Request method distribution
- Status code distribution
- Top domains accessed

## Troubleshooting

### Connection Refused
- Ensure the proxy is running
- Check host and port configuration
- Verify firewall settings

### SSL Certificate Errors
- For HTTPS tunneling, no certificate installation needed
- For full decryption, install generated certificate
- Some applications may reject self-signed certificates

### No Traffic Visible
- Verify application proxy configuration
- Check that application supports proxy settings
- Try verbose mode (`-v`) for more details

### Performance Issues
- Reduce `--max-body-size` for large payloads
- Disable body viewing if not needed
- Use filters to reduce output

### Memory Usage
- Request history limited to 1000 entries
- Large bodies may consume memory
- Consider using filters for long sessions

## File Formats

### HAR (HTTP Archive)

Standard format for HTTP traffic:
- Widely supported
- Can be opened in browser DevTools
- Includes all request/response data
- JSON-based structure

### Log Files

Plain text format:
- Timestamped entries
- Human-readable
- Can be grepped/searched
- Useful for auditing

## Security Considerations

- Only run on localhost (127.0.0.1) unless specifically needed
- Do not expose to the internet
- Be careful with root certificates
- Traffic logs may contain sensitive data
- Delete certificates after testing
- Use strong file permissions for logs
- Avoid logging credentials

## Performance

- Minimal overhead for tunneling
- Body inspection adds processing time
- JSON formatting requires parsing
- Filtering improves performance
- Statistics tracked in real-time
- Thread-safe for concurrent connections

## Limitations

- HTTPS bodies encrypted without certificate installation
- Some applications bypass system proxy
- WebSocket support is limited
- Large requests/responses consume memory
- No support for HTTP/2 server push
- Binary content shown as size only

## Contributing

This tool is designed for defensive security and development. Contributions that enhance security analysis capabilities are welcome, but features that could be used maliciously will not be accepted.

## License

This project is provided as-is for educational and development purposes.

## Changelog

### Version 4.0 (Graphical User Interface)
- Added complete GUI application (gui.py)
- Modern tkinter-based interface
- Live traffic monitoring with real-time updates
- Interactive request/response viewer with tabs
- Visual decoding panel for JWT, cookies, form data
- Proxy control panel (start/stop, configuration)
- Advanced filtering interface
- Statistics dashboard with metrics
- HAR export/import functionality
- Request replay interface
- Built-in decoder tools (Base64, JWT, URL)
- Dark/Light theme support
- Cross-platform support (Windows, macOS, Linux)
- Launch scripts for easy startup
- Comprehensive GUI documentation

### Version 3.0 (Advanced Decoding)
- Added comprehensive decoding module (decoders.py)
- Added JWT token decoding with timestamp conversion
- Added Basic Authentication Base64 decoding
- Added Cookie parsing and display
- Added Set-Cookie attribute parsing
- Added form data decoding (application/x-www-form-urlencoded)
- Added multipart form data parsing
- Added HTML pretty printing
- Added XML pretty printing
- Added binary hex dump viewer
- Added character encoding detection
- Added URL/percent encoding decoder
- Added standalone decoder CLI tool
- Auto-decode headers (Authorization, Cookie, Set-Cookie)
- Auto-decode request/response bodies based on Content-Type
- Added --decode/--no-decode flags for control

### Version 2.0 (Enhanced)
- Added request/response body viewing
- Added JSON pretty printing
- Added advanced filtering (domain, method, status)
- Added statistics tracking
- Added request history
- Added HAR export
- Added request replay tool
- Added traffic analyzer
- Added response time tracking
- Added content decompression
- Improved error handling
- Enhanced output formatting

### Version 1.0 (Initial)
- Basic HTTP/HTTPS proxy
- CONNECT tunneling
- Verbose mode
- File logging
- SSL certificate generator

## Disclaimer

The authors are not responsible for any misuse of this tool. Users are responsible for ensuring they have proper authorization before monitoring any network traffic. Always comply with applicable laws and regulations.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.
