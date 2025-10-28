# HTTP/HTTPS Traffic Viewer - GUI Documentation

A modern graphical user interface for the HTTP/HTTPS Traffic Viewer with comprehensive features for monitoring, analyzing, and debugging network traffic.

## Features

### 🖥️ Modern Interface
- Clean, intuitive design
- Multi-panel layout for easy navigation
- Real-time traffic updates
- Dark/Light theme support
- Cross-platform (Windows, macOS, Linux)

### 📡 Proxy Control
- Start/Stop proxy with one click
- Configurable host and port
- Real-time status indicators
- Verbose and decoding options
- Quick configuration changes

### 📊 Traffic Monitoring
- Live traffic list with auto-refresh
- Color-coded by status (success, error, etc.)
- Sortable columns (Method, Host, Path, Status, Size, Time)
- Request/Response details viewer
- Automatic body decoding

### 🔍 Advanced Features
- **Filtering**: Filter by domain, method, or status code
- **Search**: Quick search through traffic
- **Statistics**: Real-time traffic statistics
- **HAR Export/Import**: Save and load traffic captures
- **Request Replay**: Replay captured requests
- **Decoder Tools**: Quick decode JWT, Base64, etc.
- **Decoded View**: Automatic decoding of auth, cookies, forms

## Installation

### Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- Required Python modules (automatically imported)

### Verify Requirements

```bash
# Check Python version
python3 --version

# Check if tkinter is available
python3 -c "import tkinter; print('tkinter is available')"
```

### Install tkinter (if needed)

**Ubuntu/Debian:**
```bash
sudo apt-get install python3-tk
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install python3-tkinter
```

**macOS:**
```bash
# tkinter is usually included with Python from python.org
# If using Homebrew:
brew install python-tk
```

**Windows:**
tkinter is included with the standard Python installer from python.org

## Launching the GUI

### Linux/macOS

```bash
# Using the launcher script
./launch_gui.sh

# Or directly
python3 gui.py
```

### Windows

```batch
REM Using the launcher
launch_gui.bat

REM Or directly
python gui.py
```

## User Interface Guide

### Main Window Layout

```
┌──────────────────────────────────────────────────────────────────┐
│ File  View  Tools  Help                                   [Menu] │
├────────────────────┬─────────────────────────────────────────────┤
│ Proxy Control      │ Request/Response Details                    │
│  ┌──────────────┐  │  ┌─────────────────────────────────────────┐│
│  │ Host: IP     │  │  │ Overview | Headers | Req Body | Resp    ││
│  │ Port: 8888   │  │  │          Body | Decoded                  ││
│  │ [Start/Stop] │  │  │                                          ││
│  └──────────────┘  │  │  Selected request details displayed here ││
│                    │  │                                          ││
│ Filters            │  └─────────────────────────────────────────┘│
│  Domain:           │                                              │
│  Method:           │                                              │
│  Status:           │                                              │
│  [Apply]           │                                              │
│                    │                                              │
│ Traffic List       │                                              │
│  # Method Host Path│                                              │
│  1 GET example.com │                                              │
│  2 POST api.test   │                                              │
│  ...               │                                              │
└────────────────────┴─────────────────────────────────────────────┘
│ Status: Ready                                                     │
└───────────────────────────────────────────────────────────────────┘
```

### Control Panel

Located on the left side, provides proxy configuration and control:

#### Proxy Settings
- **Host**: IP address to bind proxy (default: 127.0.0.1)
- **Port**: Port number for proxy (default: 8888)
- **Start/Stop Button**: Toggle proxy server

#### Options
- **Verbose**: Show all headers and details
- **Auto-decode**: Automatically decode content (JWT, Base64, etc.)

#### Filters
- **Domain**: Filter traffic by domain name
- **Method**: Filter by HTTP method (GET, POST, etc.)
- **Status**: Filter by status code (200, 404, etc.)
- **Apply**: Apply current filters

### Traffic List

Displays all captured HTTP/HTTPS requests in real-time:

**Columns:**
- **#**: Request number
- **Method**: HTTP method (GET, POST, etc.)
- **Host**: Target host/domain
- **Path**: Request path (truncated)
- **Status**: HTTP status code
- **Size**: Response body size
- **Time**: Response time in milliseconds

**Color Coding:**
- 🟢 **Green**: Success (2xx)
- 🔵 **Blue**: Redirect (3xx)
- 🟠 **Orange**: Client Error (4xx)
- 🔴 **Red**: Server Error (5xx)

**Interactions:**
- Click any row to view details
- Auto-scrolls to latest traffic
- Double-click to quick-view

### Details Panel

Shows comprehensive information about selected request:

#### Overview Tab
- Request method, URL, version
- Host information
- Status code and text
- Response time
- Request/Response sizes
- Timestamp

#### Headers Tab
- **Request Headers**: All headers sent by client
- **Response Headers**: All headers from server
- Syntax highlighted
- Copyable text

#### Request Body Tab
- Complete request body
- Automatic formatting (JSON, XML, HTML)
- Binary data indication
- Syntax highlighting

#### Response Body Tab
- Complete response body
- Automatic JSON pretty printing
- HTML/XML formatting
- Binary data indication
- Syntax highlighting

#### Decoded Tab
- **Automatically decoded content:**
  - Basic Auth credentials
  - JWT tokens (header + payload)
  - Parsed cookies
  - Form data fields
  - Multipart data
- JSON formatted output
- Shows only if decodable content exists

## Menu Bar Features

### File Menu

**Export to HAR...**
- Save captured traffic to HAR file
- Standard format for sharing
- Can be opened in browser DevTools
- Preserves all request/response data

**Load HAR...**
- Import previously saved traffic
- Analyze traffic from other sources
- Add to current session

**Clear Traffic**
- Remove all captured requests
- Confirms before clearing
- Cannot be undone

**Exit**
- Close the application
- Prompts if proxy is running

### View Menu

**Toggle Theme**
- Switch between light and dark themes
- Applies immediately
- Persists during session

**Statistics**
- Opens statistics window
- Shows comprehensive metrics:
  - Total requests
  - Average response time
  - HTTP methods distribution
  - Status codes breakdown
  - Top domains
  - Percentages and charts

### Tools Menu

**Request Replay**
- Replay selected request
- Modify target host
- Useful for testing
- Shows request details before replay

**Decoder**
- Quick decoder tool
- Tabs for different formats:
  - **Base64**: Decode Base64 strings
  - **JWT**: Parse JWT tokens with timestamps
  - **URL**: Decode percent-encoded URLs
  - **Cookies**: Parse cookie strings
  - **Hex**: Convert hex to text
- Real-time decoding
- Copy results

### Help Menu

**About**
- Application information
- Version number
- Feature list
- Credits

## Common Workflows

### 1. Basic Traffic Monitoring

```
1. Launch GUI
2. Configure Host/Port if needed
3. Click "Start Proxy"
4. Configure your app to use proxy
5. Watch traffic appear in real-time
6. Click any request to see details
```

### 2. Debug API Issues

```
1. Start proxy
2. Set Domain filter to API domain
3. Monitor requests
4. Click failed request (red)
5. Check Response Body tab for error
6. Check Headers for auth issues
7. Use Decoded tab for JWT inspection
```

### 3. Analyze Authentication Flow

```
1. Start proxy with Auto-decode enabled
2. Filter by Method: POST
3. Perform login in target app
4. Select login request
5. Go to Decoded tab
6. View decoded credentials/tokens
7. Verify JWT claims and expiration
```

### 4. Export Traffic for Analysis

```
1. Capture desired traffic
2. File → Export to HAR
3. Choose filename and location
4. Share with team or analyze later
5. Or use traffic_analyzer.py on HAR
```

### 5. Test API Changes

```
1. Capture production request
2. Select the request
3. Tools → Request Replay
4. Modify host to staging/dev
5. Click Replay
6. Compare results
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+E | Export to HAR |
| Ctrl+L | Load HAR |
| Ctrl+D | Clear Traffic |
| Ctrl+T | Toggle Theme |
| Ctrl+S | Show Statistics |
| Ctrl+R | Request Replay |
| Ctrl+Q | Quit |
| F5 | Refresh View |
| Delete | Clear Selected |

## Tips & Tricks

### Performance

- **Use Filters**: Reduce noise by filtering relevant traffic
- **Clear Regularly**: Clear old traffic to maintain performance
- **Close Other Tabs**: Focus on needed information
- **Disable Auto-decode**: For large volumes if not needed

### Analysis

- **Sort Columns**: Click column headers to sort
- **Color Coding**: Quick identification of status types
- **Time Column**: Identify slow requests
- **Size Column**: Find large payloads

### Workflow

- **Export Before Clearing**: Save important sessions
- **Use Statistics**: Get overview before diving deep
- **Decoder Tool**: Quick checks without full capture
- **Theme Toggle**: Reduce eye strain in different lighting

## Troubleshooting

### GUI Won't Start

**Error: tkinter not found**
```bash
# Install tkinter
sudo apt-get install python3-tk  # Ubuntu/Debian
sudo yum install python3-tkinter  # CentOS/RHEL
```

**Error: Module not found**
```bash
# Ensure you're in the correct directory
cd /path/to/http-https-viewer
python3 gui.py
```

### Proxy Won't Start

**Port Already in Use**
- Change port number in GUI
- Kill process using the port
- Use different port (e.g., 9000)

**Permission Denied**
- Don't use ports < 1024 without sudo
- Use ports >= 1024 (8888, 9000, etc.)

### No Traffic Appearing

**App Not Using Proxy**
- Verify proxy configuration in target app
- Check host:port match GUI settings
- Some apps bypass system proxy

**Firewall Blocking**
- Check firewall rules
- Allow traffic on proxy port
- Use localhost (127.0.0.1)

### GUI Freezing

**Too Much Traffic**
- Use filters to reduce volume
- Clear old traffic regularly
- Disable verbose mode if not needed

**Large Responses**
- Bodies are truncated automatically
- Consider using CLI for bulk capture

## Advanced Features

### Custom Filtering

Filters support partial matching:
- **Domain**: `api` matches `api.example.com`
- **Status**: Empty = show all, `404` = only 404s

### HAR Files

HAR files can be:
- Opened in Chrome DevTools (Network tab)
- Analyzed with `traffic_analyzer.py`
- Shared with team members
- Used for documentation

### Request Replay

Replay features:
- Modify target host/port
- Keep original headers
- Useful for testing across environments
- Shows response in dialog

### Statistics Window

Provides insights:
- Request distribution
- Performance metrics
- Error rates
- Domain analysis

## Security Considerations

### Sensitive Data

- GUI may display passwords, tokens, etc.
- Be careful when sharing screenshots
- Clear traffic before sharing computer
- Don't export sensitive HAR files

### Proxy Usage

- Only use on localhost (127.0.0.1)
- Don't expose to network
- Only monitor apps you own
- Follow legal and ethical guidelines

### Data Storage

- Traffic kept in memory only
- Not saved unless exported
- Cleared on exit
- HAR exports may contain secrets

## Comparison: CLI vs GUI

| Feature | CLI | GUI |
|---------|-----|-----|
| Real-time view | ✅ | ✅ |
| Traffic history | Limited | ✅ Full |
| Filtering | Basic | ✅ Advanced |
| Decoding | ✅ Auto | ✅ Auto + Visual |
| Export HAR | ✅ | ✅ |
| Statistics | On exit | ✅ Anytime |
| Request replay | Separate tool | ✅ Integrated |
| Ease of use | Moderate | ✅ Easy |
| Resource usage | ✅ Low | Moderate |
| Scripting | ✅ | ❌ |
| Remote use | ✅ SSH | ❌ |

**Use CLI when:**
- Running on remote server
- Automating tasks
- Minimal resource usage needed
- No display available

**Use GUI when:**
- Interactive analysis
- Visual debugging
- Quick inspection
- Learning/demonstration

## Extending the GUI

The GUI is built with tkinter and can be extended:

```python
# Add custom decoder
def my_custom_decoder(data):
    # Your decoding logic
    return decoded_data

# Add to decoder dialog
# See gui.py for implementation
```

## Known Limitations

1. **HTTPS Bodies**: Encrypted unless cert installed
2. **WebSocket**: Limited support
3. **HTTP/2**: Not fully supported
4. **Large Files**: Bodies truncated for performance
5. **Memory**: Traffic stored in RAM

## Future Enhancements

Planned features:
- Search/filter in request bodies
- Export specific requests
- Compare requests
- Custom color schemes
- Regex filtering
- Traffic diff viewer
- Performance graphs
- WebSocket support

## Support

For issues or questions:
- Check documentation first
- Review troubleshooting section
- Check GitHub issues
- Create new issue with details

## Credits

Built with:
- Python 3
- tkinter for GUI
- http_https_viewer.py for proxy
- decoders.py for content decoding

---

**Remember**: This tool is for defensive security and development purposes only.
Only use on systems you own or have explicit permission to monitor.
