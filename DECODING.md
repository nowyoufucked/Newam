# Advanced Decoding Features

The HTTP/HTTPS Traffic Viewer includes comprehensive decoding capabilities to automatically decode and parse various content types and encodings.

## 🔓 Auto-Decoding Features

### Headers Decoding

#### **Authorization Header**
- **Basic Auth**: Automatically decodes Base64 encoded credentials
- **Bearer (JWT)**: Automatically decodes and parses JWT tokens
  - Shows header algorithm and type
  - Displays payload claims
  - Converts timestamps to readable format

**Example Output:**
```
Authorization: Bearer eyJhbGc...
  [JWT Decoded]:
    Header: {
      "alg": "HS256",
      "typ": "JWT"
    }
    Payload: {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022,
      "iat_readable": "2018-01-18T01:30:22"
    }
```

#### **Cookie Header**
- Parses multiple cookies from Cookie header
- Displays each cookie name and value
- Truncates long cookie values for readability

**Example Output:**
```
Cookie: session=abc123; user=john; preferences=...
  [Parsed Cookies]:
    session: abc123
    user: john
    preferences: eyJ0aGVtZSI6ImRhcmsiLCJsYW5nIjoiZW4ifQ==
```

#### **Set-Cookie Header**
- Parses Set-Cookie with all attributes
- Shows domain, path, expiration, flags

**Example Output:**
```
Set-Cookie: sessionid=abc123; Path=/; HttpOnly; Secure
  [Parsed Set-Cookie]:
    path: /
    httponly: True
    secure: True
```

### Body Content Decoding

#### **Form Data (application/x-www-form-urlencoded)**
- Automatically parses form-encoded data
- Displays key-value pairs
- URL-decodes values

**Example:**
```
[Decoded Form Data]:
  username: john.doe
  email: john@example.com
  message: Hello World!
```

#### **Multipart Form Data**
- Parses multipart/form-data boundaries
- Shows each part with name, filename, size
- Displays text content inline
- Indicates binary files

**Example:**
```
[Decoded Multipart Data]:
  Part 1:
    Name: username
    Size: 8 bytes
    Content: john.doe

  Part 2:
    Name: avatar
    Filename: profile.jpg
    Size: 15432 bytes
```

#### **JSON Pretty Printing**
- Auto-detects JSON content
- Formats with proper indentation
- Works with application/json and JSON-like content

**Example:**
```json
{
  "user": {
    "id": 123,
    "name": "John Doe",
    "roles": ["admin", "user"]
  }
}
```

#### **HTML Pretty Printing**
- Formats HTML with proper indentation
- Makes HTML structure more readable
- Truncates very large HTML documents

**Example:**
```html
<html>
  <head>
    <title>Example</title>
  </head>
  <body>
    <h1>Hello World</h1>
  </body>
</html>
```

#### **XML Pretty Printing**
- Uses xml.dom.minidom for proper formatting
- Handles namespaces and attributes
- Falls back to basic formatting if needed

**Example:**
```xml
<?xml version="1.0"?>
<root>
  <item id="1">
    <name>Example</name>
  </item>
</root>
```

#### **Binary Data Hex Dump**
- Shows hex dump for binary content
- Includes ASCII representation
- Truncated to configurable size

**Example:**
```
[Hex Dump]:
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 00 00 20 00 00 00 20  08 06 00 00 00 73 7a 7a  |... ... .....szz|
... (truncated at 256 bytes)
```

## 🛠️ Standalone Decoder Tool

Use `decoders.py` for quick decoding tasks:

```bash
# Decode Base64
python decoders.py --base64 "SGVsbG8gV29ybGQh"

# Decode JWT
python decoders.py --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# URL decode
python decoders.py --url "Hello%20World%21"

# Parse cookies
python decoders.py --cookies "session=abc123; user=john"

# Parse form data
python decoders.py --form "username=john&email=john%40example.com"

# Convert hex to text
python decoders.py --hex "48656c6c6f"
```

## 📋 Supported Decodings

### Compression
- gzip
- deflate
- brotli (if brotli module installed)

### Character Encodings
- UTF-8
- Latin-1 / ISO-8859-1
- CP1252
- ASCII

### Content Types
- JSON (application/json)
- Form Data (application/x-www-form-urlencoded)
- Multipart (multipart/form-data)
- HTML (text/html)
- XML (application/xml, text/xml)
- Plain Text
- Binary (hex dump)

### Authentication & Tokens
- Basic Authentication (Base64)
- JWT (JSON Web Tokens)
- Bearer tokens

### Data Formats
- Base64
- URL/Percent encoding
- Hex encoding
- Cookies

## 🎯 Usage

### Enable Auto-Decoding (Default)
```bash
python http_https_viewer.py -b
# or explicitly
python http_https_viewer.py -b --decode
```

### Disable Auto-Decoding
```bash
python http_https_viewer.py -b --no-decode
```

### View All Decoded Content
```bash
python http_https_viewer.py -v -b
```

## 💡 Use Cases

### 1. API Token Analysis
```bash
# Monitor and decode JWT tokens in API requests
python http_https_viewer.py --filter-domain api.myapp.com -b
```

### 2. Form Debugging
```bash
# See exactly what form data is being sent
python http_https_viewer.py --filter-method POST -b
```

### 3. Cookie Investigation
```bash
# Analyze cookie values and attributes
python http_https_viewer.py -v -b
```

### 4. Authentication Debugging
```bash
# Decode Basic Auth and Bearer tokens
python http_https_viewer.py -v
```

### 5. Binary Protocol Analysis
```bash
# View hex dumps of binary data
python http_https_viewer.py -b --max-body-size 512
```

## ⚙️ Configuration

**Max Body Size**: Control how much data to decode
```bash
python http_https_viewer.py -b --max-body-size 20000
```

**Disable Specific Decodings**: Use `--no-decode` to see raw data
```bash
python http_https_viewer.py -b --no-decode
```

## 🔒 Security Notes

- **Sensitive Data**: Decoded content may contain passwords, tokens, and PII
- **Logging**: Be careful when saving decoded content to files
- **JWT Signatures**: Tokens are decoded but NOT verified
- **Basic Auth**: Credentials are shown in plaintext after decoding
- **Use Responsibly**: Only on systems you own or have permission to monitor

## 📊 Example Session

```bash
# Start proxy with decoding
python http_https_viewer.py -v -b

# In another terminal, make authenticated request
curl -X POST http://httpbin.org/post \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Cookie: session=abc123; user=john" \
  -d "username=test&password=secret" \
  -x http://127.0.0.1:8888
```

**Output will show:**
- Decoded JWT header and payload
- Parsed cookies
- Decoded form data
- Response body formatted (if JSON/HTML/XML)

## 🧪 Testing Decoders

Test individual decoders:
```bash
# Base64
echo "SGVsbG8gV29ybGQh" | python decoders.py --base64

# URL encoding
python decoders.py --url "name%3DJohn%20Doe"

# JWT (use a sample token)
python decoders.py --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

## 📚 Implementation Details

- **Thread-Safe**: All decoders can be used concurrently
- **Error Tolerant**: Failed decodings fall back to raw display
- **Memory Efficient**: Large bodies are truncated
- **Extensible**: Easy to add new decoders

For more information, see the source code in `decoders.py` and `http_https_viewer.py`.
