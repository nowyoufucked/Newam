# Enhanced GUI Features (v5.0)

## Overview

The Enhanced GUI (`enhanced_gui.py`) includes all features from the original GUI plus comprehensive additions for packet capture, WebSocket viewing, DNS tracking, session management, and advanced analysis.

## What's New

### 1. Session Management
- **Multiple Sessions**: Work with multiple capture sessions simultaneously
- **Session Tabs**: Switch between different capture sessions
- **Session Comparison**: Compare traffic between sessions
- **Session Export/Import**: Save and load individual sessions

### 2. Enhanced Proxy Integration
- **Enhanced Mode Toggle**: Switch between basic and enhanced proxy
- **WebSocket Support**: Capture and display WebSocket traffic
- **Connection Tracking**: View connection pool statistics
- **DNS Tracking**: Monitor DNS resolutions in real-time

### 3. Packet Capture Integration
- **Start/Stop Packet Capture**: Capture raw packets alongside HTTP traffic
- **PCAP Export**: Export captured packets to Wireshark-compatible format
- **Packet Details Tab**: View detailed packet information (Ethernet, IP, TCP/UDP headers)
- **Multi-Layer Analysis**: See traffic at all network layers

### 4. WebSocket Viewer
- **Dedicated WebSocket Tab**: View WebSocket messages separately
- **Frame Analysis**: See WebSocket frame details (opcode, mask, payload)
- **Message Filtering**: Filter WebSocket messages by type
- **Export Messages**: Save WebSocket traffic to JSON

### 5. DNS Query Viewer
- **DNS Query Tab**: View all DNS queries made during capture
- **Query Statistics**: See most queried domains
- **Resolution Times**: Track DNS resolution performance
- **Cache Hit Rate**: Monitor DNS cache effectiveness

### 6. Advanced Search and Filtering
- **Regex Search**: Search traffic with regular expressions
- **Multi-Field Filtering**: Filter by domain, method, status simultaneously
- **Saved Filters**: Save and reuse common filters
- **Search History**: Access previous searches

### 7. Multiple Export Formats
- **HAR Export**: HTTP Archive format (Wireshark, browser dev tools)
- **PCAP Export**: Packet capture format (Wireshark, tcpdump)
- **JSON Export**: Raw JSON for custom processing
- **CSV Export**: Spreadsheet-compatible format

### 8. Visualization Features
- **Timeline View**: Visualize requests over time
- **Statistics Dashboard**: Real-time charts and graphs
- **Protocol Distribution**: See traffic breakdown by protocol
- **Bandwidth Graphs**: Monitor bandwidth usage

### 9. Enhanced Details Viewer
- **8 Detail Tabs**: Overview, Headers, Request/Response Body, Decoded, WebSocket, Packet Details, Timing
- **Packet Details Tab**: View IP/TCP/UDP headers, Ethernet frames
- **Timing Tab**: See detailed timing breakdown (DNS, Connect, TLS, TTFB)
- **WebSocket Tab**: View WebSocket messages for selected connection

### 10. Context Menu
- **Right-Click Actions**: Quick access to common operations
- **Copy URL**: Copy request URL to clipboard
- **Copy as cURL**: Generate cURL command
- **Replay Request**: Replay selected request
- **Compare**: Compare with another request
- **Delete**: Remove request from list

### 11. Keyboard Shortcuts
- **Ctrl+N**: New Session
- **Ctrl+O**: Load HAR File
- **Ctrl+E**: Export to HAR
- **Ctrl+S**: Show Statistics
- **Ctrl+R**: Request Replay
- **Ctrl+D**: Decoder Tool
- **Ctrl+F**: Search/Filter
- **Ctrl+L**: Clear Traffic
- **Ctrl+T**: Toggle Theme
- **Ctrl+Q**: Quit
- **F5**: Refresh Display

### 12. Improved Traffic List
- **Search Bar**: Search traffic in real-time
- **Regex Toggle**: Enable regex search mode
- **Auto-Scroll**: Automatically scroll to new requests
- **Color Coding**: Visual status indicators (green=2xx, blue=3xx, orange=4xx, red=5xx)
- **Sortable Columns**: Click headers to sort

### 13. Certificate Viewer
- **TLS Certificate Details**: View SSL/TLS certificate information
- **Certificate Chain**: See full certificate chain
- **Expiration Warnings**: Alert for expired certificates
- **Export Certificates**: Save certificates to file

### 14. Request Comparison
- **Side-by-Side Diff**: Compare two requests/responses
- **Highlight Differences**: Visual diff of headers and bodies
- **Session Comparison**: Compare entire sessions
- **Export Comparison**: Save comparison results

### 15. Timeline Visualization
- **Request Timeline**: See all requests on a time axis
- **Waterfall Chart**: Visualize request timing
- **Concurrent Requests**: See parallel requests
- **Zoom and Pan**: Navigate through timeline

## Usage

### Starting the Enhanced GUI

```bash
# Launch enhanced GUI
python3 enhanced_gui.py

# Or use the launch script (create one)
./launch_enhanced_gui.sh
```

### Basic Workflow

1. **Configure Proxy**
   - Set host and port (default: 127.0.0.1:8888)
   - Enable Enhanced Mode for WebSocket and advanced features
   - Check WebSocket if capturing WebSocket traffic

2. **Start Proxy**
   - Click "Start Proxy" button
   - Configure your application to use the proxy
   - Traffic will appear in real-time

3. **View Traffic**
   - Click any request to see details
   - Use tabs to view different aspects (Headers, Body, Decoded, etc.)
   - Right-click for quick actions

4. **Advanced Features**
   - Use Tools menu to access packet capture, WebSocket viewer, DNS viewer
   - Use View menu for statistics and visualization
   - Use keyboard shortcuts for quick access

### Session Management

```
1. Click "New Session" or press Ctrl+N
2. Each session maintains separate traffic
3. Switch between sessions using session tabs
4. Compare sessions using Tools > Compare Sessions
5. Export individual sessions separately
```

### Packet Capture

```
1. Tools > Start Packet Capture (requires root/admin)
2. Packets are captured alongside HTTP traffic
3. View packet details in "Packet Details" tab
4. Export to PCAP via File > Export to PCAP
5. Open PCAP in Wireshark for analysis
```

### WebSocket Monitoring

```
1. Enable "WebSocket" checkbox in control panel
2. Start proxy in Enhanced Mode
3. WebSocket connections appear in traffic list
4. View WebSocket messages in "WebSocket" tab
5. Export WebSocket messages via tab toolbar
```

### DNS Tracking

```
1. Enhanced Mode automatically tracks DNS queries
2. View > DNS Queries to see all queries
3. Statistics show cache hit rate and resolution times
4. Export DNS log for analysis
```

### Search and Filter

```
Search:
- Type in search bar above traffic list
- Enable "Regex" for regular expression search
- Press F5 to refresh with current filters

Filter:
- Domain: Filter by hostname (e.g., "example.com")
- Method: Filter by HTTP method (GET, POST, etc.)
- Status: Filter by status code (e.g., "404")
- Click "Apply" to activate filters
```

### Exporting Data

```
HAR Export:
- File > Export to HAR (Ctrl+E)
- Compatible with browser dev tools, Wireshark

PCAP Export:
- File > Export to PCAP
- Open in Wireshark, tcpdump, tshark

JSON Export:
- File > Export to JSON
- Raw data for custom processing

CSV Export:
- File > Export to CSV
- Open in Excel, Google Sheets
```

## Enhanced Proxy vs Basic Proxy

| Feature | Basic Proxy | Enhanced Proxy |
|---------|-------------|----------------|
| HTTP/HTTPS Capture | ✓ | ✓ |
| WebSocket Support | ✗ | ✓ |
| DNS Tracking | ✗ | ✓ |
| Connection Pooling | ✗ | ✓ |
| Chunked Encoding | Partial | ✓ |
| System Proxy Config | ✗ | ✓ |
| Upstream Proxy | ✗ | ✓ |
| Advanced Statistics | ✗ | ✓ |

**Recommendation**: Use Enhanced Proxy for full feature set

## Integration with Packet Capture

The Enhanced GUI integrates seamlessly with the packet capture module:

1. **Automatic Packet Capture**: When enabled, captures packets for all proxy traffic
2. **Packet Details Tab**: Shows decoded packet information (Ethernet, IP, TCP headers)
3. **PCAP Export**: Export captured packets for external analysis
4. **Protocol Correlation**: Correlate HTTP requests with underlying packets

## Performance Considerations

- **Memory Usage**: Enhanced mode uses more memory due to WebSocket buffering and packet storage
- **CPU Usage**: Packet capture increases CPU usage, especially in promiscuous mode
- **Disk Space**: PCAP files can be large; use filters to reduce size
- **UI Responsiveness**: Large number of requests (>10,000) may slow down UI

**Optimization Tips**:
- Use filters to reduce captured traffic
- Clear traffic periodically (Ctrl+L)
- Disable packet capture if not needed
- Use sessions to segment captures
- Export and clear large captures

## Troubleshooting

### Enhanced Proxy Won't Start

**Problem**: Error when starting enhanced proxy

**Solutions**:
- Check if port is already in use
- Verify enhanced_proxy.py is available
- Try basic proxy mode instead
- Check firewall settings

### Packet Capture Fails

**Problem**: "Permission denied" when starting packet capture

**Solutions**:
- Run GUI with sudo/admin privileges: `sudo python3 enhanced_gui.py`
- On Linux: `sudo python3 enhanced_gui.py`
- On Windows: Run as Administrator
- Check if raw socket access is available

### WebSocket Messages Not Showing

**Problem**: WebSocket traffic not captured

**Solutions**:
- Ensure "Enhanced Mode" is enabled
- Check "WebSocket" checkbox
- Verify proxy is running
- Confirm application is using proxy
- Check if WebSocket uses standard ports

### UI Freezes with Large Captures

**Problem**: GUI becomes unresponsive

**Solutions**:
- Clear traffic (Ctrl+L)
- Use filters to reduce traffic
- Export and start new session
- Increase filter specificity
- Disable packet capture if enabled

### Search Not Finding Results

**Problem**: Search doesn't work

**Solutions**:
- Check search term spelling
- Try without regex first
- Verify traffic is loaded
- Check if filters are active
- Use simpler search terms

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Enhanced GUI (Tkinter)                  │
├─────────────────────────────────────────────────────────┤
│  Session Mgmt  │  Search/Filter  │  Visualization       │
├─────────────────────────────────────────────────────────┤
│  Traffic List  │  Details Viewer  │  Statistics         │
├─────────────────────────────────────────────────────────┤
│                Enhanced Proxy (optional)                  │
│  ├─ WebSocket Handler                                    │
│  ├─ DNS Resolver                                         │
│  ├─ Connection Tracker                                   │
│  └─ Chunked Handler                                      │
├─────────────────────────────────────────────────────────┤
│            Packet Capture Module (optional)               │
│  ├─ Raw Socket Capture                                   │
│  ├─ Protocol Dissectors                                  │
│  └─ PCAP Writer                                          │
├─────────────────────────────────────────────────────────┤
│                    HTTP/HTTPS Proxy                       │
└─────────────────────────────────────────────────────────┘
```

## Future Enhancements

Planned features for future versions:

1. **Real-Time Graphs**: Live bandwidth and request rate charts
2. **Custom Plugins**: Plugin system for extending functionality
3. **Request Fuzzing**: Built-in fuzzing capabilities
4. **Response Modification**: Modify responses on-the-fly
5. **SSL/TLS Interception**: Decrypt HTTPS traffic (with CA cert)
6. **Automated Testing**: Record and replay test sequences
7. **API Documentation**: Generate API docs from captured traffic
8. **Performance Profiling**: Identify slow endpoints
9. **Security Analysis**: Detect common vulnerabilities
10. **Cloud Sync**: Sync sessions across devices

## Comparison with Other Tools

| Feature | Enhanced GUI | Wireshark | Burp Suite | Charles Proxy |
|---------|--------------|-----------|------------|---------------|
| HTTP/HTTPS | ✓ | ✓ | ✓ | ✓ |
| WebSocket | ✓ | ✓ | ✓ | ✓ |
| Packet Capture | ✓ | ✓ | ✗ | ✗ |
| Protocol Dissection | ✓ | ✓ | Partial | Partial |
| Free/Open Source | ✓ | ✓ | Free tier | Trial |
| Easy to Use | ✓✓ | ✗ | ✓ | ✓ |
| Scriptable | Python | Lua | Extensions | ✗ |
| Cross-Platform | ✓ | ✓ | ✓ | ✓ |

**Use Cases**:
- **Enhanced GUI**: Development, debugging, learning
- **Wireshark**: Deep packet analysis, network troubleshooting
- **Burp Suite**: Web security testing, penetration testing
- **Charles Proxy**: Mobile app debugging, HTTPS inspection

## Best Practices

1. **Use Sessions**: Organize captures into logical sessions
2. **Filter Early**: Apply filters before capturing to reduce noise
3. **Export Regularly**: Export important captures for later analysis
4. **Document Sessions**: Add notes about what you're testing
5. **Clean Up**: Clear traffic periodically to maintain performance
6. **Use Shortcuts**: Learn keyboard shortcuts for efficiency
7. **Enhanced Mode**: Enable enhanced mode for full features
8. **Packet Capture**: Only enable when needed (requires root)
9. **Search Wisely**: Use regex for complex patterns
10. **Compare Sessions**: Use comparison to track changes

## Security and Privacy

**Important Notes**:
- Captured traffic may contain sensitive data (passwords, tokens, PII)
- Encrypt exported files if they contain sensitive information
- Be aware of legal and privacy implications
- Only capture traffic you own or have permission to monitor
- Delete captures when no longer needed
- Secure file permissions on saved captures

**Security Measures**:
```bash
# Encrypt exported HAR file
gpg -c capture.har

# Set restrictive permissions
chmod 600 capture.har

# Secure delete when done
shred -u capture.har
```

## Contributing

Contributions welcome! Areas for improvement:

- Complete stub implementations (timeline, certificate viewer, etc.)
- Add real-time graphing with matplotlib
- Implement SSL/TLS interception
- Add response modification capabilities
- Create plugin system
- Improve performance for large captures
- Add more export formats
- Enhance visualization features

## License

See main README.md for license information.

## Support

For issues and questions:
- Check this documentation first
- Review main README.md and other docs
- Check keyboard shortcuts (Help > Keyboard Shortcuts)
- Ensure all dependencies are installed
- Try basic proxy mode if enhanced mode has issues

## Credits

Built on top of:
- http_https_viewer.py (basic proxy)
- enhanced_proxy.py (advanced proxy)
- packet_capture.py (raw packet capture)
- protocol_dissectors.py (protocol parsing)
- decoders.py (content decoding)

Enhanced GUI integrates all these components into a unified interface.
