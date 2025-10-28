#!/usr/bin/env python3
"""
Decoders Module
===============
Comprehensive decoding utilities for HTTP traffic analysis.

Supports:
- Character encoding detection and conversion
- Base64 decoding
- URL/percent encoding
- Form data parsing
- Cookie parsing
- JWT token decoding
- HTML/XML pretty printing
- Hex dump for binary data
- Multipart form data
"""

import base64
import json
import re
from urllib.parse import unquote, parse_qs, parse_qsl
from datetime import datetime
import binascii


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'


class ContentDecoder:
    """Decode various content types and encodings"""

    @staticmethod
    def detect_encoding(data):
        """Detect character encoding of data"""
        try:
            # Try common encodings
            encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252', 'ascii']
            for encoding in encodings:
                try:
                    data.decode(encoding)
                    return encoding
                except:
                    continue
            return 'utf-8'  # Default
        except:
            return 'utf-8'

    @staticmethod
    def decode_base64(data):
        """Decode Base64 data"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            # Remove whitespace
            data = data.strip()

            # Add padding if needed
            missing_padding = len(data) % 4
            if missing_padding:
                data += b'=' * (4 - missing_padding)

            decoded = base64.b64decode(data)
            return decoded
        except Exception as e:
            return None

    @staticmethod
    def decode_url(data):
        """Decode URL/percent encoded data"""
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='replace')
            return unquote(data)
        except:
            return data

    @staticmethod
    def parse_form_data(data, content_type=''):
        """Parse form data (application/x-www-form-urlencoded)"""
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='replace')

            parsed = parse_qsl(data, keep_blank_values=True)
            return dict(parsed)
        except Exception as e:
            return None

    @staticmethod
    def parse_cookies(cookie_string):
        """Parse cookie header"""
        try:
            if isinstance(cookie_string, bytes):
                cookie_string = cookie_string.decode('utf-8', errors='replace')

            cookies = {}
            for item in cookie_string.split(';'):
                item = item.strip()
                if '=' in item:
                    key, value = item.split('=', 1)
                    cookies[key.strip()] = value.strip()
            return cookies
        except:
            return {}

    @staticmethod
    def parse_set_cookie(set_cookie_string):
        """Parse Set-Cookie header with attributes"""
        try:
            if isinstance(set_cookie_string, bytes):
                set_cookie_string = set_cookie_string.decode('utf-8', errors='replace')

            parts = set_cookie_string.split(';')
            cookie = {}

            # First part is name=value
            if parts and '=' in parts[0]:
                name, value = parts[0].split('=', 1)
                cookie['name'] = name.strip()
                cookie['value'] = value.strip()

            # Parse attributes
            for part in parts[1:]:
                part = part.strip()
                if '=' in part:
                    key, val = part.split('=', 1)
                    cookie[key.strip().lower()] = val.strip()
                else:
                    cookie[part.lower()] = True

            return cookie
        except:
            return {}

    @staticmethod
    def decode_jwt(token):
        """Decode JWT token (without verification)"""
        try:
            if isinstance(token, bytes):
                token = token.decode('utf-8')

            # Remove 'Bearer ' prefix if present
            token = token.replace('Bearer ', '').strip()

            parts = token.split('.')
            if len(parts) != 3:
                return None

            header_data = ContentDecoder.decode_base64(parts[0])
            payload_data = ContentDecoder.decode_base64(parts[1])

            if not header_data or not payload_data:
                return None

            header = json.loads(header_data.decode('utf-8'))
            payload = json.loads(payload_data.decode('utf-8'))

            # Parse timestamps
            if 'exp' in payload:
                try:
                    payload['exp_readable'] = datetime.fromtimestamp(payload['exp']).isoformat()
                except:
                    pass
            if 'iat' in payload:
                try:
                    payload['iat_readable'] = datetime.fromtimestamp(payload['iat']).isoformat()
                except:
                    pass
            if 'nbf' in payload:
                try:
                    payload['nbf_readable'] = datetime.fromtimestamp(payload['nbf']).isoformat()
                except:
                    pass

            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except Exception as e:
            return None

    @staticmethod
    def parse_multipart(data, boundary):
        """Parse multipart form data"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            if isinstance(boundary, str):
                boundary = boundary.encode('utf-8')

            parts = []
            boundary_delim = b'--' + boundary

            sections = data.split(boundary_delim)

            for section in sections[1:-1]:  # Skip first and last
                if not section.strip():
                    continue

                # Split headers and body
                if b'\r\n\r\n' in section:
                    headers_data, body = section.split(b'\r\n\r\n', 1)
                elif b'\n\n' in section:
                    headers_data, body = section.split(b'\n\n', 1)
                else:
                    continue

                # Parse headers
                headers = {}
                for line in headers_data.split(b'\r\n'):
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        headers[key.decode('utf-8', errors='replace').strip()] = \
                            value.decode('utf-8', errors='replace').strip()

                # Extract name and filename from Content-Disposition
                name = None
                filename = None
                if 'Content-Disposition' in headers:
                    cd = headers['Content-Disposition']
                    name_match = re.search(r'name="([^"]+)"', cd)
                    if name_match:
                        name = name_match.group(1)
                    filename_match = re.search(r'filename="([^"]+)"', cd)
                    if filename_match:
                        filename = filename_match.group(1)

                parts.append({
                    'name': name,
                    'filename': filename,
                    'headers': headers,
                    'body': body.rstrip(b'\r\n')
                })

            return parts
        except Exception as e:
            return None

    @staticmethod
    def hex_dump(data, length=256, width=16):
        """Create hex dump of binary data"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            if len(data) > length:
                data = data[:length]
                truncated = True
            else:
                truncated = False

            lines = []
            for i in range(0, len(data), width):
                chunk = data[i:i+width]

                # Hex representation
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                hex_part = hex_part.ljust(width * 3)

                # ASCII representation
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

                lines.append(f'{i:08x}  {hex_part}  |{ascii_part}|')

            result = '\n'.join(lines)
            if truncated:
                result += f'\n... (truncated at {length} bytes)'

            return result
        except:
            return None

    @staticmethod
    def pretty_print_html(html):
        """Pretty print HTML (basic indentation)"""
        try:
            if isinstance(html, bytes):
                html = html.decode('utf-8', errors='replace')

            # Basic HTML formatting
            html = re.sub(r'>\s*<', '>\n<', html)

            lines = html.split('\n')
            indented = []
            indent = 0

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Decrease indent for closing tags
                if line.startswith('</'):
                    indent = max(0, indent - 1)

                indented.append('  ' * indent + line)

                # Increase indent for opening tags (not self-closing)
                if line.startswith('<') and not line.startswith('</') and not line.endswith('/>'):
                    if not any(line.startswith(f'<{tag}') for tag in ['br', 'hr', 'img', 'input', 'meta', 'link']):
                        indent += 1

            return '\n'.join(indented[:100])  # Limit to 100 lines
        except:
            return None

    @staticmethod
    def pretty_print_xml(xml):
        """Pretty print XML (basic indentation)"""
        try:
            if isinstance(xml, bytes):
                xml = xml.decode('utf-8', errors='replace')

            # Try using xml.dom.minidom for better formatting
            try:
                import xml.dom.minidom
                dom = xml.dom.minidom.parseString(xml)
                return dom.toprettyxml(indent='  ')[:2000]  # Limit size
            except:
                # Fallback to basic formatting
                return ContentDecoder.pretty_print_html(xml)
        except:
            return None


class DecoderDisplay:
    """Display decoded content in formatted way"""

    @staticmethod
    def display_base64(data, label="Base64"):
        """Display Base64 decoded content"""
        decoded = ContentDecoder.decode_base64(data)
        if decoded:
            print(f"\n{Colors.OKCYAN}{label} Decoded:{Colors.ENDC}")
            try:
                # Try to display as text
                text = decoded.decode('utf-8', errors='replace')
                if len(text) < 500:
                    print(f"{Colors.GRAY}{text}{Colors.ENDC}")
                else:
                    print(f"{Colors.GRAY}{text[:500]}...{Colors.ENDC}")
            except:
                # Binary data - show hex dump
                hex_dump = ContentDecoder.hex_dump(decoded, 128)
                print(f"{Colors.GRAY}{hex_dump}{Colors.ENDC}")
            return True
        return False

    @staticmethod
    def display_jwt(token, label="JWT Token"):
        """Display decoded JWT"""
        decoded = ContentDecoder.decode_jwt(token)
        if decoded:
            print(f"\n{Colors.OKCYAN}{label}:{Colors.ENDC}")
            print(f"{Colors.BOLD}Header:{Colors.ENDC}")
            print(f"{Colors.GRAY}{json.dumps(decoded['header'], indent=2)}{Colors.ENDC}")
            print(f"{Colors.BOLD}Payload:{Colors.ENDC}")
            print(f"{Colors.GRAY}{json.dumps(decoded['payload'], indent=2)}{Colors.ENDC}")
            print(f"{Colors.BOLD}Signature:{Colors.ENDC} {decoded['signature'][:32]}...")
            return True
        return False

    @staticmethod
    def display_cookies(cookies, label="Cookies"):
        """Display parsed cookies"""
        if cookies:
            print(f"\n{Colors.OKCYAN}{label}:{Colors.ENDC}")
            for name, value in cookies.items():
                if len(value) > 50:
                    value = value[:50] + '...'
                print(f"  {Colors.BOLD}{name}{Colors.ENDC}: {value}")
            return True
        return False

    @staticmethod
    def display_form_data(data, label="Form Data"):
        """Display parsed form data"""
        if data:
            print(f"\n{Colors.OKCYAN}{label}:{Colors.ENDC}")
            for key, value in data.items():
                print(f"  {Colors.BOLD}{key}{Colors.ENDC}: {value}")
            return True
        return False

    @staticmethod
    def display_multipart(parts, label="Multipart Data"):
        """Display parsed multipart data"""
        if parts:
            print(f"\n{Colors.OKCYAN}{label}:{Colors.ENDC}")
            for i, part in enumerate(parts, 1):
                print(f"\n  {Colors.BOLD}Part {i}:{Colors.ENDC}")
                if part['name']:
                    print(f"    Name: {part['name']}")
                if part['filename']:
                    print(f"    Filename: {part['filename']}")
                print(f"    Size: {len(part['body'])} bytes")

                # Show content if text
                if part['headers'].get('Content-Type', '').startswith('text'):
                    try:
                        text = part['body'].decode('utf-8', errors='replace')
                        if len(text) < 200:
                            print(f"    Content: {text}")
                        else:
                            print(f"    Content: {text[:200]}...")
                    except:
                        pass
            return True
        return False

    @staticmethod
    def display_hex_dump(data, label="Hex Dump"):
        """Display hex dump"""
        hex_dump = ContentDecoder.hex_dump(data)
        if hex_dump:
            print(f"\n{Colors.OKCYAN}{label}:{Colors.ENDC}")
            print(f"{Colors.GRAY}{hex_dump}{Colors.ENDC}")
            return True
        return False


def main():
    """Interactive decoder tool"""
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description='Decode various content types',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --base64 "SGVsbG8gV29ybGQ="
  %(prog)s --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  %(prog)s --url "Hello%20World%21"
  %(prog)s --cookies "session=abc123; user=john"
  %(prog)s --hex "48656c6c6f"
        """
    )

    parser.add_argument('--base64', help='Decode Base64 string')
    parser.add_argument('--jwt', help='Decode JWT token')
    parser.add_argument('--url', help='Decode URL encoded string')
    parser.add_argument('--cookies', help='Parse cookie string')
    parser.add_argument('--form', help='Parse form data')
    parser.add_argument('--hex', help='Convert hex string to text')

    args = parser.parse_args()

    if args.base64:
        DecoderDisplay.display_base64(args.base64, "Base64 Input")

    if args.jwt:
        DecoderDisplay.display_jwt(args.jwt, "JWT Token")

    if args.url:
        decoded = ContentDecoder.decode_url(args.url)
        print(f"\n{Colors.OKCYAN}URL Decoded:{Colors.ENDC}")
        print(f"{Colors.GRAY}{decoded}{Colors.ENDC}")

    if args.cookies:
        cookies = ContentDecoder.parse_cookies(args.cookies)
        DecoderDisplay.display_cookies(cookies, "Parsed Cookies")

    if args.form:
        form_data = ContentDecoder.parse_form_data(args.form)
        DecoderDisplay.display_form_data(form_data, "Parsed Form Data")

    if args.hex:
        try:
            hex_str = args.hex.replace(' ', '').replace('0x', '')
            data = bytes.fromhex(hex_str)
            text = data.decode('utf-8', errors='replace')
            print(f"\n{Colors.OKCYAN}Hex Decoded:{Colors.ENDC}")
            print(f"{Colors.GRAY}{text}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Error decoding hex: {e}{Colors.ENDC}")

    if not any([args.base64, args.jwt, args.url, args.cookies, args.form, args.hex]):
        parser.print_help()


if __name__ == '__main__':
    main()
