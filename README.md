# HTTP/HTTPS Traffic Viewer - Enhanced Edition

A powerful Python-based proxy server for monitoring, analyzing, and replaying HTTP and HTTPS traffic from targeted applications.

## ⚠️ Important Security Warning

**This tool is intended for DEFENSIVE SECURITY and DEVELOPMENT purposes only.**

- ✅ Use on applications you own or develop
- ✅ Use for debugging and testing your own software
- ✅ Use for security research on systems you have permission to test
- ❌ DO NOT use to intercept traffic without authorization
- ❌ DO NOT use to capture credentials or sensitive data from others
- ❌ Unauthorized interception of network traffic may be illegal in your jurisdiction

## Features

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

## Tools Included

1. **http_https_viewer.py** - Main proxy server with enhanced features
2. **request_replay.py** - Replay requests from HAR files
3. **traffic_analyzer.py** - Analyze captured traffic and generate reports
4. **cert_generator.py** - Generate SSL certificates (optional)
5. **example_client.py** - Test client for proxy validation

## Requirements

- Python 3.6 or higher
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

### Main Proxy Server

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
