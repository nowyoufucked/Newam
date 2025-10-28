# Windows Troubleshooting Guide

## WinError 10013: Port Access Denied

This error occurs when Windows blocks access to the network port (default 8888).

### Quick Fix (Try These First)

#### Solution 1: Use a Different Port ⭐ EASIEST

The simplest solution is to use a different port that isn't blocked:

**Command Line:**
```cmd
python3 http_https_viewer.py -p 9000 -v -b
```

**GUI:**
1. Start the GUI: `python3 enhanced_gui.py`
2. Change the port from `8888` to `9000` in the Port field
3. Click "Start Proxy"

**Common alternative ports to try:**
- `9000` (recommended)
- `8080` (common HTTP alternative)
- `8889` (close to default)
- `3128` (proxy standard)
- `5000` (development)

#### Solution 2: Find Available Port Automatically

Run the port finder script:
```cmd
python3 find_available_port.py
```

This will tell you which port is available and how to use it.

#### Solution 3: Run as Administrator

1. Right-click on Command Prompt
2. Select "Run as Administrator"
3. Navigate to the project directory
4. Run the command again:
   ```cmd
   cd C:\Users\menonic\Downloads\Newam\Newam-claude-http-https-viewer-011CUYx3QtxzWiCHHS8TvyTx
   python3 enhanced_gui.py
   ```

---

## Detailed Troubleshooting

### Check What's Using Port 8888

Run this command to see if something is already using port 8888:
```cmd
netstat -ano | findstr :8888
```

If you see output like:
```
TCP    0.0.0.0:8888    0.0.0.0:0    LISTENING    12345
```

The last number (12345) is the Process ID (PID). You can:

1. **Find what program it is:**
   ```cmd
   tasklist | findstr 12345
   ```

2. **Kill the process (if safe):**
   ```cmd
   taskkill /PID 12345 /F
   ```

   **⚠️ Warning:** Only kill the process if you know what it is!

### Windows Firewall Configuration

If Windows Firewall is blocking the port:

1. **Open Windows Firewall:**
   - Press `Windows + R`
   - Type `firewall.cpl`
   - Press Enter

2. **Allow Python through firewall:**
   - Click "Allow an app or feature through Windows Defender Firewall"
   - Click "Change settings" (may need administrator)
   - Click "Allow another app..."
   - Browse to your Python installation:
     - Common locations:
       - `C:\Program Files\Python3X\python.exe`
       - `C:\Users\[YourName]\AppData\Local\Programs\Python\Python3X\python.exe`
       - `C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.13_...\python.exe`
   - Add it and make sure both "Private" and "Public" are checked
   - Click OK

3. **Or create a firewall rule:**
   ```cmd
   REM Run as Administrator
   netsh advfirewall firewall add rule name="Python HTTP Proxy" dir=in action=allow protocol=TCP localport=8888
   ```

### Port Conflicts with Other Software

Common software that might use port 8888:

- **Other proxy servers** (Fiddler, Charles, Burp Suite)
- **Development servers** (Node.js, webpack-dev-server)
- **Other instances** of this tool
- **VMware** or **VirtualBox** services
- **Jenkins** or other CI/CD tools

**Check and close these if running.**

### Windows Reserved Ports

Some ports are reserved by Windows and can't be used without administrator privileges:

- Ports 0-1023 are "well-known ports" (need admin)
- Some dynamic ports may be reserved by Windows

**Solution:** Use ports above 1024 and below 49152 (like 8888, 9000, 8080)

### Hyper-V Port Exclusions

If you have Hyper-V enabled, it may reserve certain ports:

1. **Check reserved ports:**
   ```cmd
   netsh interface ipv4 show excludedportrange protocol=tcp
   ```

2. **If 8888 is in an excluded range**, use a different port outside the range.

### Antivirus Software

Some antivirus software blocks socket operations:

- **Windows Defender** - Usually okay
- **Third-party AV** - May block, check settings
- **Corporate security software** - May restrict all proxies

**Solution:**
1. Add Python to antivirus exceptions
2. Or use a different port
3. Or temporarily disable (if safe to do so)

### Python Installation Issues

If Python doesn't have proper permissions:

1. **Reinstall Python** with "Add Python to PATH" checked
2. **Install for all users** (requires admin during install)
3. **Use Windows Store version** (often has better permissions)

### Quick Test Commands

```cmd
REM Test if Python is working
python3 --version

REM Test if port is available
python3 find_available_port.py

REM Test with different port
python3 http_https_viewer.py -p 9000 -v -b

REM Check what's using ports
netstat -ano | findstr LISTENING
```

---

## Alternative: Use Basic GUI Without Errors

The basic GUI handles port conflicts more gracefully:

```cmd
python3 gui.py
```

Then:
1. Set port to `9000` (or whatever port is available)
2. Click Start

---

## Recommended Workflow for Windows Users

1. **First Time Setup:**
   ```cmd
   REM Find available port
   python3 find_available_port.py

   REM Note the available port (e.g., 9000)
   ```

2. **Start GUI with that port:**
   ```cmd
   python3 enhanced_gui.py
   ```

3. **In GUI:**
   - Change port to the available port you found
   - Click "Start Proxy"
   - Configure your browser/app to use `127.0.0.1:[PORT]`

---

## Configuration Tips

### Save Your Port Preference

Edit the default port in the code (one-time change):

**For enhanced_gui.py:**
```python
# Find line ~56:
self.config = {
    'host': '127.0.0.1',
    'port': 9000,  # Change this from 8888 to 9000
    # ...
}
```

**For http_https_viewer.py:**
```python
# Find line ~15:
DEFAULT_PORT = 9000  # Change from 8888
```

### Create a Custom Launcher

Create `start_proxy.bat` with your preferred port:
```batch
@echo off
python3 enhanced_gui.py
REM The GUI will remember your last port setting
pause
```

---

## Still Having Issues?

If none of the above work:

1. **Check Windows Event Viewer:**
   - Press `Windows + R`
   - Type `eventvwr.msc`
   - Look in "Windows Logs" > "Application" for Python errors

2. **Try a completely different port range:**
   ```cmd
   python3 http_https_viewer.py -p 5000
   python3 http_https_viewer.py -p 7000
   python3 http_https_viewer.py -p 3000
   ```

3. **Check for port exhaustion:**
   ```cmd
   netstat -ano | find /c "ESTABLISHED"
   ```
   If this shows thousands of connections, you may have port exhaustion.

4. **Restart Windows** (sometimes fixes network stack issues)

5. **Run with maximum verbosity:**
   ```cmd
   python3 http_https_viewer.py -p 9000 -v
   ```

---

## Prevention

To avoid this issue in the future:

1. **Always use ports above 1024**
2. **Use uncommon ports** like 9000, 9100, 7500
3. **Check availability before starting** with `find_available_port.py`
4. **Close proxy when done** to free the port
5. **Don't run multiple instances** on the same port

---

## Command Reference

```cmd
REM Find available port
python3 find_available_port.py

REM Check port usage
netstat -ano | findstr :8888

REM Start with custom port
python3 http_https_viewer.py -p 9000 -v -b
python3 enhanced_gui.py  # Then change port in GUI

REM Kill process by PID
taskkill /PID [PID] /F

REM Add firewall rule (as Admin)
netsh advfirewall firewall add rule name="Python Proxy" dir=in action=allow protocol=TCP localport=9000

REM Check firewall rules
netsh advfirewall firewall show rule name=all | findstr Python
```

---

## Success Checklist

✅ Tried a different port (9000, 8080, etc.)
✅ Ran find_available_port.py to find free port
✅ Checked for other applications using the port
✅ Ran as Administrator
✅ Added Python to Windows Firewall exceptions
✅ Closed other proxy tools (Fiddler, Charles, etc.)
✅ Restarted Command Prompt
✅ Restarted Windows

If you've tried all of these and it still doesn't work, there may be corporate security policies or network restrictions in place.

---

## Contact & Support

- Check README.md for basic usage
- Check GUI_ENHANCEMENTS.md for GUI features
- Check ADVANCED.md for proxy features
- Check PACKET_ANALYSIS.md for packet capture

**Remember:** The simplest solution is usually to **just use a different port**! Port 9000 works great on most Windows systems.
