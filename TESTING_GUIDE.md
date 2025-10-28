# Complete Testing Guide for Windows

## ⚠️ IMPORTANT: HTTP vs HTTPS

**What you're seeing is ENCRYPTED HTTPS traffic, not plain HTTP!**

```
←[92m[timestamp] Server -> Client: 99 bytes←[0m    ← Encrypted TLS data
←[96m[timestamp] Client -> Server: 558 bytes←[0m  ← Encrypted TLS data
```

These messages mean:
- ✅ Proxy is working and relaying traffic
- ❌ But it's only seeing **encrypted bytes**, not actual HTTP requests
- ❌ So there's **nothing to display** in the GUI (no parsed requests)

## Why GUI is Blank

The GUI is blank because:
1. HTTPS traffic is **encrypted**
2. The proxy can't read the actual requests inside the encryption
3. It only logs "Client -> Server" bytes (which are useless for analysis)
4. `self.history.requests` is EMPTY (nothing to show in GUI)

## Solution: Test with Plain HTTP

You need to test with **plain HTTP** (not HTTPS) first to verify the GUI works.

---

## 🧪 Testing Method 1: Local HTTP Server (BEST)

### Step 1: Start Test HTTP Server

Open **Command Prompt #1**:
```cmd
cd C:\Users\menonic\Downloads\Newam\Newam-claude-http-https-viewer-011CUYx3QtxzWiCHHS8TvyTx

python3 test_http_server.py
```

You should see:
```
HTTP Test Server for Proxy Testing
Server running on: http://127.0.0.1:8000
```

**Keep this window open!**

### Step 2: Start Proxy GUI

Open **Command Prompt #2**:
```cmd
cd C:\Users\menonic\Downloads\Newam\Newam-claude-http-https-viewer-011CUYx3QtxzWiCHHS8TvyTx

python3 fixed_gui.py
```

1. Click "Start Proxy"
2. Should show: 🟢 Running on 127.0.0.1:9000

### Step 3: Configure Browser

**Firefox** (Recommended):
1. Settings → General → Network Settings → Settings button
2. Select "Manual proxy configuration"
3. HTTP Proxy: `127.0.0.1`
4. Port: `9000`
5. **UNCHECK** "Also use this proxy for HTTPS"  ← IMPORTANT!
6. Click OK

**Chrome**:
1. Settings → System → Open your computer's proxy settings
2. LAN settings
3. Proxy server: `127.0.0.1:9000`

### Step 4: Generate HTTP Traffic

In your browser, visit:
```
http://127.0.0.1:8000/test
```

**What Should Happen:**

**Command Prompt #1 (Test Server):**
```
[TEST SERVER] 127.0.0.1 - "GET /test HTTP/1.1" 200 -
```

**Command Prompt #2 (Proxy Terminal):**
```
[timestamp] GET http://127.0.0.1:8000/test → 200 OK (10ms)
[GUI] Found 1 new requests  ← THIS LINE IS CRITICAL!
```

**GUI Window:**
- ✅ Request appears in traffic list
- ✅ Shows: GET | 127.0.0.1:8000 | /test | 200
- ✅ Click to see full details

---

## 🧪 Testing Method 2: Using Test HTML Page

### Step 1: Open Test Page

1. Save `test_proxy.html` (already created)
2. Open it in your browser:
   ```
   file:///C:/Users/menonic/Downloads/Newam/Newam-claude-http-https-viewer-011CUYx3QtxzWiCHHS8TvyTx/test_proxy.html
   ```

3. Configure browser proxy (see above)

4. Click the test buttons

5. Watch the GUI!

---

## 🧪 Testing Method 3: Command Line (curl)

This **bypasses browser** entirely:

```cmd
REM Test with proxy
curl -x http://127.0.0.1:9000 -v http://httpbin.org/get

REM Or with local test server
curl -x http://127.0.0.1:9000 -v http://127.0.0.1:8000/test
```

**Expected Output:**
```
* Using proxy http://127.0.0.1:9000
> GET http://httpbin.org/get HTTP/1.1
< HTTP/1.1 200 OK
```

**And in proxy terminal:**
```
[timestamp] GET http://httpbin.org/get → 200 OK
[GUI] Found 1 new requests
```

---

## ✅ Success Checklist

When working properly, you'll see:

### In Proxy Terminal:
```
[timestamp] GET http://127.0.0.1:8000/test → 200 OK (5ms)
[GUI] Found 1 new requests
```

### In GUI:
```
#  Method  Host              Path    Status  Size   Time
1  GET     127.0.0.1:8000    /test   200     250B   5ms
```

### Click the request to see:
- ✅ Request headers
- ✅ Response headers
- ✅ Response body (JSON)
- ✅ All details

---

## ❌ Common Issues

### Issue 1: Only See "Server -> Client" Messages

**Problem:** Only encrypted HTTPS traffic
**Solution:** Use plain HTTP (http:// not https://)

### Issue 2: "Connection Refused" Error

**Problem:** Test server not running
**Solution:** Start test_http_server.py first

### Issue 3: Browser Uses HTTPS Anyway

**Problem:** Browser forces HTTPS redirect
**Solution:**
- Use local test server (http://127.0.0.1:8000)
- Or disable HTTPS in browser proxy settings

### Issue 4: No "[GUI] Found" Message

**Problem:** GUI not polling properly
**Solution:**
```cmd
REM Pull latest fixes
git pull

REM Try again
python3 fixed_gui.py
```

---

## 🔍 Debugging Steps

### 1. Verify Proxy is Receiving Traffic

**In proxy terminal, you should see EITHER:**

**✅ GOOD (HTTP):**
```
[timestamp] GET http://example.com → 200 OK
```

**❌ BAD (HTTPS only):**
```
[timestamp] Client -> Server: 558 bytes
[timestamp] Server -> Client: 1460 bytes
```

If you only see the "bytes" messages, you're only sending HTTPS traffic!

### 2. Verify GUI is Polling

**Look for this message:**
```
[GUI] Found X new requests
```

If you don't see this message, the GUI isn't detecting requests.

### 3. Check History Count

Add this test:

```python
# In fixed_gui.py, add to update_traffic():
if self.proxy and hasattr(self.proxy, 'history'):
    count = len(self.proxy.history.requests)
    print(f"[DEBUG] History has {count} requests")
```

---

## 🎯 Quick Test Procedure

**Complete test in 2 minutes:**

1. **Terminal 1:** `python3 test_http_server.py`
2. **Terminal 2:** `python3 fixed_gui.py` → Click "Start Proxy"
3. **Browser:** Configure proxy 127.0.0.1:9000
4. **Browser:** Visit `http://127.0.0.1:8000/test`
5. **Check Terminal 2:** Should see "[GUI] Found 1 new requests"
6. **Check GUI:** Request should appear in list

**If this works:** ✅ GUI is working perfectly!

**If this doesn't work:** Something else is wrong (not the HTTPS issue)

---

## 🔐 About HTTPS Support

### Why HTTPS Doesn't Show in GUI

HTTPS traffic is:
1. **Encrypted** with TLS/SSL
2. Proxy can't read the content
3. Only sees encrypted bytes
4. Can't parse HTTP headers/body
5. Nothing to add to history
6. GUI stays empty

### To Capture HTTPS (Advanced)

You would need:
1. SSL/TLS MITM (Man-in-the-Middle)
2. Generate CA certificate
3. Install cert in browser
4. Proxy decrypts and re-encrypts traffic
5. **This is complex and NOT currently implemented**

For now: **Use HTTP for testing!**

---

## 📊 Test Results

After following this guide, you should have:

| Test | Expected Result |
|------|----------------|
| Test Server Running | ✅ "Server running on http://127.0.0.1:8000" |
| Proxy GUI Running | ✅ "🟢 Running on 127.0.0.1:9000" |
| Visit http://127.0.0.1:8000/test | ✅ Request in GUI |
| "[GUI] Found" message | ✅ Appears in terminal |
| GUI shows request | ✅ In traffic list |
| Click request | ✅ Shows full details |

---

## 🆘 Still Not Working?

If you've done all this and GUI is still empty:

1. **Confirm HTTP (not HTTPS):**
   ```cmd
   curl -x http://127.0.0.1:9000 http://127.0.0.1:8000/test
   ```

2. **Check proxy terminal:**
   - Should see: "GET http://127.0.0.1:8000/test → 200 OK"
   - Should see: "[GUI] Found 1 new requests"

3. **If you see the GET line but NOT the [GUI] line:**
   - The GUI polling is broken
   - Show me the full terminal output

4. **If you don't see the GET line:**
   - Proxy isn't receiving the request
   - Check browser proxy settings
   - Try curl instead

---

## 💡 Key Takeaways

1. **HTTPS = Encrypted = Can't see requests = GUI is empty**
2. **HTTP = Plain text = Can see requests = GUI shows them**
3. **Test with local HTTP server first**
4. **Look for "[GUI] Found" message in terminal**
5. **If terminal shows the request but GUI doesn't, that's a bug**
6. **If terminal doesn't show the request, check proxy config**

---

**Ready to test? Start with Method 1 (Local HTTP Server)!**
