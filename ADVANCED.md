# Advanced Traffic Capture Features

This document describes the advanced features implemented in `enhanced_proxy.py` to ensure comprehensive traffic capture without missing any web traffic.

## Table of Contents

- [Overview](#overview)
- [WebSocket Support](#websocket-support)
- [System Proxy Configuration](#system-proxy-configuration)
- [Upstream Proxy Support](#upstream-proxy-support)
- [DNS Resolution Tracking](#dns-resolution-tracking)
- [Connection Pooling](#connection-pooling)
- [Chunked Transfer Encoding](#chunked-transfer-encoding)
- [Traffic Capture Modes](#traffic-capture-modes)
- [Redirect Handling](#redirect-handling)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

## Overview

The `enhanced_proxy.py` tool extends the basic HTTP/HTTPS viewer with advanced capabilities designed to capture ALL web traffic, including:

- Real-time bidirectional WebSocket connections
- System-wide traffic capture via automatic proxy configuration
- Proxy chaining for complex network environments
- DNS resolution tracking and caching
- HTTP keep-alive connection reuse
- Large file transfers via chunked encoding
- Multiple capture modes for different scenarios
- HTTP redirect chain tracking

### Key Benefits

1. **No Missed Traffic**: Captures WebSocket, chunked, and keep-alive connections
2. **System-Wide Coverage**: Auto-configures OS proxy settings
3. **Network Flexibility**: Works with upstream proxies and complex network setups
4. **Performance**: Connection pooling and DNS caching reduce overhead
5. **Visibility**: Tracks DNS resolutions, redirects, and connection reuse

## WebSocket Support

### What are WebSockets?

WebSockets provide full-duplex communication channels over a single TCP connection, commonly used for:
- Real-time chat applications
- Live updates and notifications
- Streaming data (stock tickers, sports scores)
- Online gaming
- Collaborative editing tools

### How It Works

1. **Upgrade Detection**: Automatically detects WebSocket upgrade requests by checking for:
   ```
   Upgrade: websocket
   Connection: Upgrade
   ```

2. **Frame Parsing**: Parses WebSocket frames according to RFC 6455:
   - Frame structure (FIN, RSV, opcode, mask, payload length)
   - Handles continuation, text, binary, close, ping, pong frames
   - Unmasks client-to-server data
   - Supports fragmented messages

3. **Bidirectional Relay**: Forwards traffic in both directions while logging:
   - Frame type and size
   - Payload content (for text frames)
   - Connection duration and frame count

### Example WebSocket Traffic

```
[WebSocket] example.com:443
  Type: text, Size: 45 bytes
  Data: {"type":"message","content":"Hello World"}

[WebSocket] example.com:443
  Type: binary, Size: 1024 bytes
  Data: [Binary data - 1024 bytes]
```

### Configuration

```python
# Enable WebSocket support (default)
viewer = EnhancedHTTPSViewer(
    port=8888,
    enable_websocket=True
)
```

## System Proxy Configuration

### Overview

Automatically configures system-wide proxy settings so ALL applications route traffic through the viewer without manual configuration.

### Supported Platforms

#### Windows
- Sets proxy via Windows Registry (`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
- Updates: `ProxyEnable`, `ProxyServer`
- Affects: Internet Explorer, Edge, Chrome (when using system settings)

#### macOS
- Uses `networksetup` command-line tool
- Configures proxy for each network service (Wi-Fi, Ethernet)
- Sets both HTTP and HTTPS proxy settings

#### Linux
- GNOME: Uses `gsettings` to configure proxy
- Environment variables: Sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`
- Affects: Most GUI and CLI applications

### Usage

```bash
# Enable system proxy configuration on startup
./enhanced_proxy.py --enable-system-proxy

# Or via Python
viewer = EnhancedHTTPSViewer(
    port=8888,
    enable_system_proxy=True
)
```

### Important Notes

- **Requires Admin/Root**: System proxy configuration requires elevated privileges on some platforms
- **Automatic Cleanup**: Proxy settings are restored when the tool exits
- **Localhost Bypass**: Local traffic (127.0.0.1, localhost) is typically not proxied
- **Security**: Use with caution in shared/production environments

## Upstream Proxy Support

### Overview

Allows the viewer to chain through another proxy server, useful for:
- Corporate networks with mandatory proxies
- SOCKS/HTTP proxy tunneling
- Load balancing and failover
- Privacy/anonymity layers

### Configuration

```bash
# Use upstream proxy
./enhanced_proxy.py --upstream-proxy http://proxy.company.com:3128

# With authentication
./enhanced_proxy.py --upstream-proxy http://user:pass@proxy.company.com:3128
```

```python
# Via Python
viewer = EnhancedHTTPSViewer(
    port=8888,
    upstream_proxy='http://proxy.company.com:3128'
)
```

### How It Works

1. **HTTP Requests**: Forwards requests to upstream proxy with full URL
2. **HTTPS Requests**: Establishes CONNECT tunnel through upstream proxy
3. **Authentication**: Supports Basic authentication via Proxy-Authorization header
4. **Error Handling**: Falls back to direct connection if upstream fails (optional)

### Example

```
Client → Enhanced Viewer (8888) → Upstream Proxy (3128) → Target Server
```

## DNS Resolution Tracking

### Overview

Tracks all DNS resolutions with timing information and caches results to improve performance.

### Features

- **Resolution Logging**: Records domain, IP, and resolution time
- **Caching**: Caches DNS results with configurable TTL (default: 300 seconds)
- **Statistics**: Tracks cache hits/misses and total resolutions
- **IPv4/IPv6**: Supports both address families

### Output Example

```
[DNS] Resolving example.com... → 93.184.216.34 (12.3ms)
[DNS] Resolving api.example.com... → 93.184.216.35 (8.7ms) [CACHED]
```

### Cache Statistics

```
DNS Statistics:
  Total Resolutions: 45
  Cache Hits: 32 (71%)
  Cache Misses: 13 (29%)
  Average Resolution Time: 10.5ms
```

### Configuration

```python
viewer = EnhancedHTTPSViewer(port=8888)
viewer.dns_resolver.cache_ttl = 600  # 10 minutes
viewer.dns_resolver.cache.clear()    # Clear cache
```

## Connection Pooling

### Overview

Reuses TCP connections for multiple requests (HTTP keep-alive), reducing:
- Connection establishment overhead
- DNS lookup frequency
- TLS handshake latency
- Network congestion

### Features

- **Automatic Keep-Alive**: Detects `Connection: keep-alive` header
- **Connection Limits**: Maximum connections per host (default: 10)
- **Idle Timeout**: Closes connections after inactivity (default: 30 seconds)
- **Thread-Safe**: Concurrent access with lock protection

### Statistics

```
Connection Pool Statistics:
  Total Connections: 25
  Active Connections: 8
  Idle Connections: 17
  Reused Connections: 143
  Connection Reuse Rate: 85%
```

### Configuration

```python
viewer = EnhancedHTTPSViewer(port=8888)
tracker = viewer.connection_tracker

# Configure limits
tracker.max_connections_per_host = 20
tracker.connection_timeout = 60

# Monitor pool
print(f"Active: {len(tracker.connections)}")
```

## Chunked Transfer Encoding

### Overview

Handles HTTP chunked transfer encoding for streaming large responses without knowing the total size upfront.

### Use Cases

- Large file downloads
- Streaming video/audio
- Server-sent events (SSE)
- Dynamic content generation

### How It Works

1. **Detection**: Identifies `Transfer-Encoding: chunked` header
2. **Chunk Reading**: Reads chunks with size prefixes:
   ```
   1a; optional-extension\r\n
   <26 bytes of data>\r\n
   0\r\n
   \r\n
   ```
3. **Assembly**: Combines chunks into complete response body
4. **Trailer Handling**: Supports optional trailing headers

### Example

```
Response:
  Transfer-Encoding: chunked
  Content-Type: application/json

Chunks:
  Chunk 1: 256 bytes
  Chunk 2: 512 bytes
  Chunk 3: 128 bytes
  Total: 896 bytes
```

## Traffic Capture Modes

### Overview

Different capture modes for various scenarios and requirements.

### Available Modes

#### 1. Promiscuous Mode (Default)
```python
capture_mode='promiscuous'
```
- Captures ALL traffic
- No filtering
- Maximum visibility
- High storage/memory usage

**Use for**: Comprehensive analysis, debugging, security auditing

#### 2. Selective Mode
```python
capture_mode='selective'
```
- Filters traffic by domain, method, status code
- Reduces noise and storage
- Configurable rules

**Use for**: Targeted monitoring, specific API debugging

**Example Configuration**:
```python
viewer.capture_mode.set_filter(
    domains=['api.example.com', 'auth.example.com'],
    methods=['POST', 'PUT'],
    status_codes=range(400, 600)  # Only errors
)
```

#### 3. Stealth Mode
```python
capture_mode='stealth'
```
- Minimal logging
- No HAR export
- Reduced performance impact
- Silent operation

**Use for**: Production monitoring, performance testing

#### 4. Debug Mode
```python
capture_mode='debug'
```
- Maximum verbosity
- Logs all internal operations
- Connection state tracking
- DNS cache dumps
- WebSocket frame details

**Use for**: Troubleshooting, development

### Switching Modes

```python
# Change mode at runtime
viewer.set_capture_mode('selective')

# Check current mode
print(viewer.get_capture_mode())
```

## Redirect Handling

### Overview

Tracks HTTP redirect chains (301, 302, 303, 307, 308) to understand the complete request flow.

### Features

- **Chain Tracking**: Records all redirects in order
- **Loop Detection**: Identifies circular redirects
- **Redirect Limits**: Prevents infinite loops (default: 10)
- **Timing**: Tracks time spent in redirects

### Output Example

```
Redirect Chain:
  1. http://example.com/ → http://www.example.com/ (301 Permanent)
  2. http://www.example.com/ → https://www.example.com/ (301 Permanent)
  3. https://www.example.com/ → https://www.example.com/en/ (302 Found)
  Total Redirects: 3
  Total Time: 234ms
```

### Configuration

```python
viewer.redirect_handler.max_redirects = 20
viewer.redirect_handler.follow_redirects = True
```

## Usage Examples

### Basic Usage

```bash
# Start with all advanced features enabled
./enhanced_proxy.py --port 8888 --enable-websocket --enable-system-proxy
```

### Corporate Network

```bash
# Use with upstream corporate proxy
./enhanced_proxy.py --port 8888 --upstream-proxy http://proxy.corp.com:8080
```

### Debug Mode

```bash
# Maximum verbosity for troubleshooting
./enhanced_proxy.py --port 8888 --capture-mode debug
```

### Selective Capture

```python
#!/usr/bin/env python3
from enhanced_proxy import EnhancedHTTPSViewer

# Create viewer
viewer = EnhancedHTTPSViewer(
    port=8888,
    enable_websocket=True,
    capture_mode='selective'
)

# Configure filters
viewer.capture_mode.set_filter(
    domains=['api.example.com'],
    methods=['POST', 'PUT', 'DELETE']
)

# Start capturing
viewer.start()
```

### WebSocket-Only Capture

```python
#!/usr/bin/env python3
from enhanced_proxy import EnhancedHTTPSViewer

viewer = EnhancedHTTPSViewer(
    port=8888,
    enable_websocket=True,
    capture_mode='selective'
)

# Only capture WebSocket traffic
viewer.capture_mode.set_filter(
    protocols=['websocket']
)

viewer.start()
```

### Statistics Dashboard

```python
#!/usr/bin/env python3
from enhanced_proxy import EnhancedHTTPSViewer
import time

viewer = EnhancedHTTPSViewer(port=8888)
viewer.start()

# Print statistics every 10 seconds
while True:
    time.sleep(10)
    stats = viewer.get_advanced_stats()
    print(f"""
    Advanced Statistics:
      WebSocket Connections: {stats['websocket_count']}
      DNS Resolutions: {stats['dns_resolutions']}
      Cached DNS: {stats['dns_cache_hits']}
      Connection Reuse: {stats['connections_reused']}
      Active Connections: {stats['active_connections']}
      Redirect Chains: {stats['redirect_chains']}
    """)
```

## Troubleshooting

### WebSocket Not Connecting

**Symptoms**: WebSocket upgrade fails or connection drops immediately

**Solutions**:
1. Check for conflicting WebSocket handlers in browser/app
2. Verify proxy supports CONNECT method
3. Ensure firewall allows bidirectional traffic
4. Try disabling compression: `Sec-WebSocket-Extensions: permessage-deflate` may cause issues

```python
# Disable WebSocket if needed
viewer = EnhancedHTTPSViewer(enable_websocket=False)
```

### System Proxy Not Working

**Symptoms**: Applications still connect directly, bypassing proxy

**Solutions**:
1. Check if running with sufficient privileges (admin/root)
2. Verify proxy settings in OS:
   - Windows: Internet Options → Connections → LAN Settings
   - macOS: System Preferences → Network → Advanced → Proxies
   - Linux: Settings → Network → Network Proxy
3. Restart applications after proxy configuration
4. Some apps ignore system proxy (use manual configuration)

```bash
# Check current proxy settings (Linux)
gsettings get org.gnome.system.proxy mode
gsettings get org.gnome.system.proxy.http host
gsettings get org.gnome.system.proxy.http port
```

### Upstream Proxy Authentication Failing

**Symptoms**: 407 Proxy Authentication Required

**Solutions**:
1. Include credentials in proxy URL: `http://user:pass@proxy:port`
2. URL-encode special characters in password
3. Check if upstream requires NTLM/Kerberos (not supported)
4. Verify credentials with direct connection: `curl -x proxy:port http://example.com`

### DNS Resolution Slow

**Symptoms**: High latency on first connection to each domain

**Solutions**:
1. Increase DNS cache TTL:
   ```python
   viewer.dns_resolver.cache_ttl = 3600  # 1 hour
   ```
2. Pre-warm DNS cache for known domains:
   ```python
   for domain in ['api.example.com', 'cdn.example.com']:
       viewer.dns_resolver.resolve(domain)
   ```
3. Use local DNS cache/resolver (e.g., dnsmasq)
4. Check `/etc/resolv.conf` for slow upstream resolvers

### Connection Pool Exhausted

**Symptoms**: Errors about maximum connections reached

**Solutions**:
1. Increase connection limit:
   ```python
   viewer.connection_tracker.max_connections_per_host = 50
   ```
2. Reduce timeout to close idle connections faster:
   ```python
   viewer.connection_tracker.connection_timeout = 15
   ```
3. Manually close connections:
   ```python
   viewer.connection_tracker.close_host('example.com')
   ```

### Chunked Encoding Errors

**Symptoms**: Incomplete responses or corrupted data

**Solutions**:
1. Verify `Transfer-Encoding: chunked` header is present
2. Check for proxy/middleware that modifies chunked responses
3. Enable debug mode to see chunk sizes:
   ```python
   viewer = EnhancedHTTPSViewer(capture_mode='debug')
   ```
4. Some servers send invalid chunk sizes - report to server admin

### High Memory Usage

**Symptoms**: Proxy process consuming excessive RAM

**Solutions**:
1. Use selective or stealth capture mode
2. Reduce connection pool size
3. Lower DNS cache size:
   ```python
   viewer.dns_resolver.cache.clear()  # Clear periodically
   ```
4. Enable response streaming for large files
5. Disable HAR export for large-scale captures

### Performance Impact

**Symptoms**: Slow application response times

**Solutions**:
1. Enable connection pooling (default)
2. Use stealth mode for minimal overhead
3. Increase worker threads:
   ```python
   viewer.max_threads = 200
   ```
4. Disable unnecessary features:
   ```python
   viewer = EnhancedHTTPSViewer(
       enable_websocket=False,  # If not needed
       enable_system_proxy=False
   )
   ```

## Best Practices

1. **Start Simple**: Begin with default settings, enable advanced features as needed
2. **Monitor Resources**: Keep an eye on memory/CPU usage, especially in debug mode
3. **Secure Credentials**: Use environment variables for upstream proxy credentials
4. **Regular Cleanup**: Clear DNS cache and close idle connections periodically
5. **Selective Capture**: Use filters to reduce noise and improve performance
6. **Test Thoroughly**: Verify WebSocket and chunked encoding with test cases
7. **Document Configs**: Keep track of custom configurations for reproducibility
8. **Update Regularly**: Stay current with protocol specifications and security updates

## Security Considerations

1. **Sensitive Data**: Captured traffic may contain passwords, tokens, API keys
2. **Storage**: Encrypt HAR files and stored traffic data
3. **Access Control**: Restrict access to proxy and captured data
4. **Upstream Proxies**: Verify trustworthiness before sending traffic through them
5. **System Proxy**: Be aware that ALL system traffic will be captured
6. **WebSocket**: Real-time traffic may include PII or confidential messages
7. **DNS Cache**: May reveal browsing patterns and accessed domains

## Performance Benchmarks

Typical overhead (compared to direct connection):

| Feature | Latency Impact | Memory Impact |
|---------|---------------|---------------|
| Basic HTTP/HTTPS | +2-5ms | ~10MB base |
| WebSocket | +1-3ms | +1-5MB per connection |
| DNS Caching | -5-20ms (after cache) | +0.1MB per 1000 entries |
| Connection Pool | -10-50ms (reused) | +0.5MB per 100 connections |
| Chunked Encoding | +1-2ms | +0.1MB buffer |
| Selective Mode | -30% (vs promiscuous) | -50% (vs promiscuous) |
| Stealth Mode | -60% (vs promiscuous) | -80% (vs promiscuous) |

*Benchmarks based on typical web traffic on Linux x64 with Python 3.9*

## Advanced Configuration

### Environment Variables

```bash
# Set DNS cache TTL
export PROXY_DNS_CACHE_TTL=3600

# Set connection timeout
export PROXY_CONN_TIMEOUT=60

# Set maximum redirects
export PROXY_MAX_REDIRECTS=20

# Enable debug logging
export PROXY_DEBUG=1
```

### Configuration File

Create `proxy_config.json`:

```json
{
  "port": 8888,
  "enable_websocket": true,
  "enable_system_proxy": false,
  "upstream_proxy": null,
  "capture_mode": "promiscuous",
  "dns_cache_ttl": 300,
  "connection_timeout": 30,
  "max_connections_per_host": 10,
  "max_redirects": 10,
  "log_level": "INFO"
}
```

Load configuration:

```python
import json
from enhanced_proxy import EnhancedHTTPSViewer

with open('proxy_config.json') as f:
    config = json.load(f)

viewer = EnhancedHTTPSViewer(**config)
viewer.start()
```

## Integration Examples

### With Selenium (Web Automation)

```python
from selenium import webdriver
from selenium.webdriver.common.proxy import Proxy, ProxyType
from enhanced_proxy import EnhancedHTTPSViewer
import threading

# Start proxy
viewer = EnhancedHTTPSViewer(port=8888)
proxy_thread = threading.Thread(target=viewer.start)
proxy_thread.daemon = True
proxy_thread.start()

# Configure Selenium
proxy = Proxy()
proxy.proxy_type = ProxyType.MANUAL
proxy.http_proxy = "127.0.0.1:8888"
proxy.ssl_proxy = "127.0.0.1:8888"

capabilities = webdriver.DesiredCapabilities.CHROME.copy()
proxy.add_to_capabilities(capabilities)

driver = webdriver.Chrome(desired_capabilities=capabilities)
driver.get("https://example.com")

# All traffic is now captured
```

### With Requests Library

```python
from enhanced_proxy import EnhancedHTTPSViewer
import requests
import threading

# Start proxy
viewer = EnhancedHTTPSViewer(port=8888)
proxy_thread = threading.Thread(target=viewer.start)
proxy_thread.daemon = True
proxy_thread.start()

# Use proxy
proxies = {
    'http': 'http://127.0.0.1:8888',
    'https': 'http://127.0.0.1:8888'
}

response = requests.get('https://api.example.com', proxies=proxies)
print(response.text)
```

### With WebSocket Client

```python
from enhanced_proxy import EnhancedHTTPSViewer
import websocket
import threading

# Start proxy with WebSocket support
viewer = EnhancedHTTPSViewer(port=8888, enable_websocket=True)
proxy_thread = threading.Thread(target=viewer.start)
proxy_thread.daemon = True
proxy_thread.start()

# Connect WebSocket through proxy
ws = websocket.WebSocket()
ws.connect(
    "ws://example.com/socket",
    http_proxy_host="127.0.0.1",
    http_proxy_port=8888
)

ws.send("Hello Server")
response = ws.recv()
print(f"Received: {response}")

# All WebSocket frames are captured
```

## API Reference

See the inline documentation in `enhanced_proxy.py` and `advanced_capture.py` for detailed API reference.

## Contributing

Improvements and bug fixes for advanced features are welcome! Please ensure:

1. Backward compatibility with basic HTTP/HTTPS viewer
2. Comprehensive error handling
3. Performance testing with benchmarks
4. Documentation updates
5. Test coverage for new protocols/features

## License

See main README.md for license information.

## Support

For issues specific to advanced features:
1. Enable debug mode: `--capture-mode debug`
2. Check logs for error messages
3. Verify feature is enabled and properly configured
4. Review this documentation for troubleshooting tips
5. Report issues with full debug output and reproduction steps
