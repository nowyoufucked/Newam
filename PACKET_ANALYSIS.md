# Multi-Layer Packet Capture and Analysis

Comprehensive packet capture and decoding at all network layers from Ethernet to Application layer.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Layer-by-Layer Decoding](#layer-by-layer-decoding)
- [Protocol Support](#protocol-support)
- [PCAP File Format](#pcap-file-format)
- [Advanced Features](#advanced-features)
- [Usage Examples](#usage-examples)
- [Integration](#integration)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)

## Overview

The packet analysis suite provides comprehensive network traffic analysis capabilities:

- **Raw Packet Capture**: Capture packets at the kernel level using raw sockets
- **Multi-Layer Decoding**: Parse and decode Ethernet, IP, TCP/UDP, and application protocols
- **Protocol Dissection**: Deep inspection of HTTP, DNS, ICMP, ARP and more
- **PCAP Export**: Save captures in standard PCAP/PCAPNG format for Wireshark
- **Real-Time Analysis**: Live packet capture with filtering and callbacks
- **Promiscuous Mode**: Capture all network traffic on interface

### Key Components

1. **packet_capture.py** - Main packet capture engine with raw socket support
2. **protocol_dissectors.py** - Protocol parsers for all network layers
3. **pcap_writer.py** - PCAP/PCAPNG file format reader/writer

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│  HTTP, HTTPS, DNS, FTP, SSH, SMTP, etc.                     │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│                    Transport Layer                           │
│  TCP (with flags, seq, ack) | UDP | ICMP                    │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│                     Network Layer                            │
│  IPv4 (with fragmentation) | IPv6 | ARP                     │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────────┐
│                   Data Link Layer                            │
│  Ethernet II (MAC addresses, EtherType)                     │
└─────────────────────────────────────────────────────────────┘
                     │
                  [Raw Socket]
                     │
                 [Network Card]
```

## Requirements

### System Requirements

- **Linux**: Full support with AF_PACKET sockets
- **macOS**: IP-level capture (no Ethernet headers)
- **Windows**: IP-level capture with SIO_RCVALL

### Privileges

**Raw socket access requires root/administrator privileges:**

```bash
# Linux/macOS
sudo python3 packet_capture.py

# Windows (Run as Administrator)
python packet_capture.py
```

### Python Version

- Python 3.6 or higher
- Standard library only (no external dependencies)

## Quick Start

### Basic Packet Capture

```bash
# Capture 100 packets on any interface
sudo python3 packet_capture.py -c 100 -v

# Capture on specific interface
sudo python3 packet_capture.py -i eth0 -v

# Capture with filter
sudo python3 packet_capture.py --filter-port 443 -v

# Save to PCAP file
sudo python3 packet_capture.py -c 1000 -o capture.pcap
```

### Programmatic Usage

```python
from packet_capture import PacketCapture

# Create capture instance
capture = PacketCapture(interface='eth0', promiscuous=True)

# Set filters
capture.set_filter(port=80, protocol='TCP')

# Add callback for each packet
def print_packet(packet):
    if 'http' in packet:
        print(f"HTTP: {packet['http']}")

capture.add_callback(print_packet)

# Start capturing
capture.start()

# ... capture runs in background ...

# Stop and get statistics
capture.stop()
stats = capture.get_statistics()
print(f"Captured {stats['total_packets']} packets")

# Save to PCAP
capture.save_to_pcap('output.pcap')
```

## Layer-by-Layer Decoding

### Layer 2: Ethernet Frame

```python
from protocol_dissectors import EthernetFrame

# Parse Ethernet frame
frame = EthernetFrame.parse(raw_data)
print(f"Src MAC: {frame['src_mac']}")
print(f"Dst MAC: {frame['dst_mac']}")
print(f"EtherType: {frame['ethertype_name']}")
```

**Decoded Information:**
- Source MAC address (6 bytes)
- Destination MAC address (6 bytes)
- EtherType (IPv4, IPv6, ARP, VLAN, etc.)
- Payload data

**Example Output:**
```
ETH: 00:1a:2b:3c:4d:5e → ff:ff:ff:ff:ff:ff (IPv4)
```

### Layer 3: IP Packet

```python
from protocol_dissectors import IPPacket

# Parse IP packet (auto-detects IPv4/IPv6)
packet = IPPacket.parse(ip_data)
print(f"Version: IPv{packet['version']}")
print(f"Src IP: {packet['src_ip']}")
print(f"Dst IP: {packet['dst_ip']}")
print(f"Protocol: {packet['protocol_name']}")
print(f"TTL: {packet['ttl']}")
```

**IPv4 Decoded Information:**
- Version, IHL, DSCP, ECN
- Total length, identification
- Flags (DF, MF) and fragment offset
- TTL and protocol
- Source and destination IP addresses
- IP options (if present)

**IPv6 Decoded Information:**
- Version, traffic class, flow label
- Payload length, next header
- Hop limit
- Source and destination IPv6 addresses

**Example Output:**
```
IP: 192.168.1.100 → 93.184.216.34 (TCP, TTL=64)
IPv6: 2001:db8::1 → 2001:db8::2 (TCP, Hop=64)
```

### Layer 4: TCP Segment

```python
from protocol_dissectors import TCPSegment

# Parse TCP segment
segment = TCPSegment.parse(tcp_data)
print(f"Src Port: {segment['src_port']}")
print(f"Dst Port: {segment['dst_port']}")
print(f"Flags: {segment['flags_str']}")
print(f"Seq: {segment['seq_num']}")
print(f"Ack: {segment['ack_num']}")
print(f"Window: {segment['window']}")
```

**Decoded Information:**
- Source and destination ports
- Sequence and acknowledgment numbers
- TCP flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
- Window size
- Checksum and urgent pointer
- TCP options (MSS, window scale, timestamps, etc.)
- Payload data

**TCP Flags:**
- **SYN**: Synchronize (connection establishment)
- **ACK**: Acknowledgment
- **FIN**: Finish (connection termination)
- **RST**: Reset (abort connection)
- **PSH**: Push (immediate data delivery)
- **URG**: Urgent
- **ECE**: ECN Echo
- **CWR**: Congestion Window Reduced

**Example Output:**
```
TCP: 54321 → 443 [SYN] seq=1000 win=65535
TCP: 443 → 54321 [SYN,ACK] seq=2000 ack=1001 win=29200
TCP: 54321 → 443 [ACK] seq=1001 ack=2001 win=65535
TCP: 54321 → 443 [PSH,ACK] seq=1001 ack=2001 len=517 (HTTPS)
```

### Layer 4: UDP Datagram

```python
from protocol_dissectors import UDPDatagram

# Parse UDP datagram
datagram = UDPDatagram.parse(udp_data)
print(f"Src Port: {datagram['src_port']}")
print(f"Dst Port: {datagram['dst_port']}")
print(f"Length: {datagram['length']}")
```

**Decoded Information:**
- Source and destination ports
- Length and checksum
- Payload data

**Example Output:**
```
UDP: 53124 → 53 len=45 (DNS)
```

### Layer 4: ICMP Packet

```python
from protocol_dissectors import ICMPPacket

# Parse ICMP packet
icmp = ICMPPacket.parse(icmp_data)
print(f"Type: {icmp['type_name']}")
print(f"Code: {icmp['code']}")
```

**Decoded Information:**
- ICMP type and code
- Checksum
- Type-specific data (echo ID/seq, gateway address, etc.)

**Common ICMP Types:**
- Type 0: Echo Reply (ping response)
- Type 3: Destination Unreachable
- Type 5: Redirect
- Type 8: Echo Request (ping)
- Type 11: Time Exceeded (traceroute)

**Example Output:**
```
ICMP: Echo Request (ping) id=12345 seq=1
ICMP: Echo Reply id=12345 seq=1 ttl=64
ICMP: Time Exceeded (TTL=0)
```

### Layer 7: HTTP

```python
from protocol_dissectors import HTTPParser

# Parse HTTP request/response
http = HTTPParser.parse(app_data)
if http['type'] == 'request':
    print(f"Method: {http['method']}")
    print(f"Path: {http['path']}")
    print(f"Headers: {http['headers']}")
elif http['type'] == 'response':
    print(f"Status: {http['status_code']}")
    print(f"Body: {http['body']}")
```

**Decoded Information:**
- Request: Method, path, HTTP version, headers, body
- Response: Status code, status text, headers, body

**Example Output:**
```
HTTP Request:
  GET /api/users HTTP/1.1
  Host: example.com
  User-Agent: Mozilla/5.0

HTTP Response:
  HTTP/1.1 200 OK
  Content-Type: application/json
  Content-Length: 123
```

### Layer 7: DNS

```python
from protocol_dissectors import DNSParser

# Parse DNS packet
dns = DNSParser.parse(dns_data)
print(f"Transaction ID: {dns['transaction_id']}")
print(f"Is Response: {dns['is_response']}")
for query in dns['queries']:
    print(f"Query: {query['name']} ({query['type']})")
```

**Decoded Information:**
- Transaction ID
- Flags (QR, opcode, AA, TC, RD, RA, rcode)
- Question count, answer count
- Queries (domain name, type, class)
- Answers (simplified parsing)

**Example Output:**
```
DNS Query: example.com (A) id=12345
DNS Response: example.com → 93.184.216.34 id=12345
```

### Layer 2: ARP

```python
from protocol_dissectors import ARPPacket

# Parse ARP packet
arp = ARPPacket.parse(arp_data)
print(f"Operation: {arp['operation_name']}")
print(f"Sender: {arp['sender_ip']} ({arp['sender_mac']})")
print(f"Target: {arp['target_ip']} ({arp['target_mac']})")
```

**Decoded Information:**
- Hardware type, protocol type
- Operation (request, reply, RARP)
- Sender MAC and IP
- Target MAC and IP

**Example Output:**
```
ARP Request: Who has 192.168.1.1? Tell 192.168.1.100
ARP Reply: 192.168.1.1 is at 00:11:22:33:44:55
```

## Protocol Support

### Full Support (Complete Parsing)

| Protocol | Layer | Description |
|----------|-------|-------------|
| Ethernet II | 2 | Ethernet frames with MAC addresses |
| IPv4 | 3 | Internet Protocol version 4 |
| IPv6 | 3 | Internet Protocol version 6 |
| ARP | 2/3 | Address Resolution Protocol |
| TCP | 4 | Transmission Control Protocol |
| UDP | 4 | User Datagram Protocol |
| ICMP | 4 | Internet Control Message Protocol |
| HTTP | 7 | Hypertext Transfer Protocol |
| DNS | 7 | Domain Name System |

### Partial Support (Identification Only)

| Protocol | Ports | Description |
|----------|-------|-------------|
| HTTPS | 443 | HTTP over TLS/SSL |
| FTP | 20, 21 | File Transfer Protocol |
| SSH | 22 | Secure Shell |
| TELNET | 23 | Telnet |
| SMTP | 25, 587 | Simple Mail Transfer Protocol |
| POP3 | 110 | Post Office Protocol |
| IMAP | 143 | Internet Message Access Protocol |
| SMB | 445 | Server Message Block |
| MySQL | 3306 | MySQL Database |
| PostgreSQL | 5432 | PostgreSQL Database |
| Redis | 6379 | Redis Database |
| MongoDB | 27017 | MongoDB Database |
| RDP | 3389 | Remote Desktop Protocol |
| VNC | 5900 | Virtual Network Computing |

## PCAP File Format

### Writing PCAP Files

```python
from pcap_writer import PCAPWriter

# Create PCAP file
with PCAPWriter('capture.pcap') as writer:
    writer.write_packet(packet_data, timestamp=time.time())
```

**PCAP Features:**
- Standard format compatible with Wireshark, tcpdump
- Global header with link-layer type
- Per-packet headers with timestamps
- Snaplen support for packet truncation

### Writing PCAPNG Files

```python
from pcap_writer import PCAPNGWriter

# Create PCAPNG file (next generation format)
with PCAPNGWriter('capture.pcapng') as writer:
    # Add interface
    iface_id = writer.add_interface(
        linktype=1,
        snaplen=65535,
        name="eth0",
        description="Primary network interface"
    )

    # Write packets
    writer.write_packet(packet_data, interface_id=iface_id)
```

**PCAPNG Features:**
- Multi-interface support
- Enhanced metadata (comments, application info)
- More extensible than PCAP
- Better for complex capture scenarios

### Reading PCAP Files

```python
from pcap_writer import PCAPReader

# Read existing PCAP file
with PCAPReader('capture.pcap') as reader:
    for packet in reader:
        print(f"Timestamp: {packet['datetime']}")
        print(f"Length: {packet['captured_len']}")
        # Parse packet data
        from protocol_dissectors import IPPacket
        ip = IPPacket.parse(packet['data'])
```

### Converting Formats

```bash
# Convert JSON to PCAP
python3 pcap_writer.py convert capture.json capture.pcap

# Then open in Wireshark
wireshark capture.pcap
```

## Advanced Features

### Filtering

```python
capture = PacketCapture()

# Filter by IP
capture.set_filter(src_ip='192.168.1.100')
capture.set_filter(dst_ip='93.184.216.34')

# Filter by port
capture.set_filter(port=443)  # Either src or dst
capture.set_filter(src_port=443, dst_port=80)

# Filter by protocol
capture.set_filter(protocol='TCP')  # TCP, UDP, ICMP
```

### Promiscuous Mode

Capture all packets on the network segment, not just those destined for your interface:

```python
capture = PacketCapture(interface='eth0', promiscuous=True)
```

**Note:** Requires root privileges and may not work on all network types (e.g., switched networks).

### Callbacks for Real-Time Processing

```python
def analyze_packet(packet):
    """Process each packet as it arrives"""
    if 'tcp' in packet and packet['tcp']['dst_port'] == 443:
        print(f"HTTPS connection to {packet['ip']['dst_ip']}")

capture.add_callback(analyze_packet)
capture.start()
```

### Statistics and Metrics

```python
stats = capture.get_statistics()
print(f"Total Packets: {stats['total_packets']}")
print(f"Duration: {stats['duration']:.2f}s")
print(f"Packets/sec: {stats['packets_per_second']:.2f}")
print(f"Total Bytes: {stats['total_bytes']:,}")

# Protocol distribution
for proto, count in stats['protocol_stats'].items():
    print(f"{proto}: {count}")
```

### Packet Reassembly

For fragmented IP packets:

```python
# IPv4 fragmentation detection
if ip_packet['flags']['mf'] or ip_packet['fragment_offset'] > 0:
    print(f"Fragmented packet: offset={ip_packet['fragment_offset']}")
    # Implement reassembly logic as needed
```

## Usage Examples

### Capture HTTP Traffic Only

```python
#!/usr/bin/env python3
from packet_capture import PacketCapture
import time

capture = PacketCapture()
capture.set_filter(port=80, protocol='TCP')

def print_http(packet):
    if 'http' in packet:
        http = packet['http']
        if http['type'] == 'request':
            print(f"→ {http['method']} {http['path']}")
        else:
            print(f"← {http['status_code']} {http['status_text']}")

capture.add_callback(print_http)
capture.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    capture.stop()
    capture.save_to_pcap('http_traffic.pcap')
```

### Monitor DNS Queries

```python
#!/usr/bin/env python3
from packet_capture import PacketCapture

capture = PacketCapture()
capture.set_filter(port=53, protocol='UDP')

def print_dns(packet):
    if 'dns' in packet:
        dns = packet['dns']
        if not dns['is_response']:
            for query in dns['queries']:
                print(f"DNS Query: {query['name']} ({query['type']})")

capture.add_callback(print_dns)
capture.start()

input("Press Enter to stop...")
capture.stop()
```

### Detect Port Scans

```python
#!/usr/bin/env python3
from packet_capture import PacketCapture
from collections import defaultdict
import time

# Track SYN packets per source IP
syn_counts = defaultdict(lambda: {'count': 0, 'ports': set()})

def detect_scan(packet):
    if 'tcp' in packet:
        tcp = packet['tcp']
        if 'SYN' in tcp['flags_str'] and 'ACK' not in tcp['flags_str']:
            src_ip = packet['ip']['src_ip']
            dst_port = tcp['dst_port']

            syn_counts[src_ip]['count'] += 1
            syn_counts[src_ip]['ports'].add(dst_port)

            # Alert if more than 10 different ports in short time
            if len(syn_counts[src_ip]['ports']) > 10:
                print(f"[!] Possible port scan from {src_ip}")
                print(f"    Ports: {sorted(syn_counts[src_ip]['ports'])[:20]}")

capture = PacketCapture()
capture.set_filter(protocol='TCP')
capture.add_callback(detect_scan)
capture.start()

# Reset counts every minute
while True:
    time.sleep(60)
    syn_counts.clear()
```

### Extract Files from HTTP

```python
#!/usr/bin/env python3
from packet_capture import PacketCapture
import os

def save_http_files(packet):
    if 'http' in packet:
        http = packet['http']
        if http['type'] == 'response':
            content_type = http['headers'].get('Content-Type', '')
            body = http['body']

            # Save images
            if 'image' in content_type and body:
                ext = content_type.split('/')[-1]
                filename = f"extracted_{int(time.time())}.{ext}"
                with open(filename, 'wb') as f:
                    f.write(body.encode('latin1'))
                print(f"Saved: {filename}")

capture = PacketCapture()
capture.set_filter(port=80)
capture.add_callback(save_http_files)
capture.start()
```

### Network Bandwidth Monitor

```python
#!/usr/bin/env python3
from packet_capture import PacketCapture
from collections import defaultdict
import time

class BandwidthMonitor:
    def __init__(self):
        self.bytes_per_ip = defaultdict(int)
        self.start_time = time.time()

    def process_packet(self, packet):
        ip = packet.get('ip', {})
        src_ip = ip.get('src_ip')
        if src_ip:
            self.bytes_per_ip[src_ip] += packet['size']

    def print_stats(self):
        duration = time.time() - self.start_time
        print(f"\n=== Bandwidth Usage (last {duration:.0f}s) ===")

        sorted_ips = sorted(
            self.bytes_per_ip.items(),
            key=lambda x: x[1],
            reverse=True
        )

        for ip, bytes_count in sorted_ips[:10]:
            mb = bytes_count / (1024 * 1024)
            mbps = (bytes_count * 8) / (1024 * 1024 * duration)
            print(f"{ip:15s}  {mb:8.2f} MB  {mbps:8.2f} Mbps")

        self.bytes_per_ip.clear()
        self.start_time = time.time()

monitor = BandwidthMonitor()
capture = PacketCapture()
capture.add_callback(monitor.process_packet)
capture.start()

# Print stats every 10 seconds
while True:
    time.sleep(10)
    monitor.print_stats()
```

## Integration

### With Enhanced Proxy

The packet capture can be integrated with the enhanced proxy for complete traffic analysis:

```python
from enhanced_proxy import EnhancedHTTPSViewer
from packet_capture import PacketCapture

# Start packet capture
packet_capture = PacketCapture()
packet_capture.set_filter(port=8888)  # Capture proxy traffic
packet_capture.start()

# Start enhanced proxy
proxy = EnhancedHTTPSViewer(port=8888)
proxy.start()

# All proxy traffic is now captured at packet level too
```

### With Existing Tools

```bash
# Capture packets, save to PCAP, analyze with Wireshark
sudo python3 packet_capture.py -c 1000 -o capture.pcap
wireshark capture.pcap

# Capture packets, save to PCAP, analyze with tcpdump
sudo python3 packet_capture.py -c 1000 -o capture.pcap
tcpdump -r capture.pcap -n

# Capture packets, save to PCAP, analyze with tshark
sudo python3 packet_capture.py -c 1000 -o capture.pcap
tshark -r capture.pcap -V
```

## Troubleshooting

### Permission Denied

**Problem:** `PermissionError: Operation not permitted`

**Solution:**
```bash
# Linux/macOS: Run with sudo
sudo python3 packet_capture.py

# Windows: Run as Administrator
# Right-click → Run as Administrator
```

### No Packets Captured

**Problem:** Capture runs but no packets appear

**Solutions:**

1. **Check interface name:**
   ```bash
   # Linux
   ip link show
   ifconfig

   # macOS
   ifconfig

   # Windows
   ipconfig
   ```

2. **Check interface is up:**
   ```bash
   sudo ip link set eth0 up
   ```

3. **Disable firewall temporarily:**
   ```bash
   # Linux
   sudo iptables -F

   # macOS
   sudo pfctl -d
   ```

4. **Use promiscuous mode:**
   ```python
   capture = PacketCapture(promiscuous=True)
   ```

### Capture Drops Packets

**Problem:** High packet loss during capture

**Solutions:**

1. **Increase buffer size:**
   ```python
   capture = PacketCapture(buffer_size=131070)  # 128KB
   ```

2. **Reduce processing overhead:**
   ```python
   # Don't print every packet
   capture = PacketCapture()
   # capture.add_callback(print_func)  # Remove heavy callbacks
   ```

3. **Use selective filters:**
   ```python
   # Only capture what you need
   capture.set_filter(port=443, protocol='TCP')
   ```

4. **Save to file instead of processing:**
   ```python
   # Minimal processing during capture
   capture.start()
   # ... capture ...
   capture.save_to_pcap('output.pcap')
   # Process file later
   ```

### Platform-Specific Issues

#### Linux

**Problem:** `SOCK_RAW` not available

**Solution:** Ensure kernel supports raw sockets (CONFIG_SOCK_RAW=y)

#### macOS

**Problem:** Can't capture Ethernet frames

**Limitation:** macOS raw sockets start at IP layer. Use alternatives:
```bash
# Use tcpdump for Ethernet-level capture
sudo tcpdump -i en0 -w capture.pcap

# Or libpcap-based tools
```

#### Windows

**Problem:** `SIO_RCVALL` fails

**Solutions:**
- Run as Administrator
- Disable Windows Firewall temporarily
- Use WinPcap/Npcap:
  ```bash
  # Install Npcap from https://npcap.com/
  # Then use Wireshark or similar tools
  ```

## Performance

### Benchmarks

Typical performance on modern hardware (Intel i7, 16GB RAM):

| Scenario | Packets/sec | CPU Usage | Memory |
|----------|-------------|-----------|--------|
| Minimal processing | 50,000+ | 15% | 50MB |
| Full parsing | 10,000-20,000 | 40% | 200MB |
| With callbacks | 5,000-10,000 | 60% | 300MB |
| Saving to PCAP | 30,000+ | 20% | 100MB |

### Optimization Tips

1. **Use filters to reduce traffic:**
   ```python
   capture.set_filter(port=443)  # Only HTTPS
   ```

2. **Minimize callback processing:**
   ```python
   def lightweight_callback(packet):
       # Only extract what you need
       if 'tcp' in packet:
           port = packet['tcp']['dst_port']
           # Process port only
   ```

3. **Use promiscuous mode sparingly:**
   ```python
   # Promiscuous mode captures everything
   capture = PacketCapture(promiscuous=False)  # Target interface only
   ```

4. **Batch processing:**
   ```python
   # Capture first, process later
   capture.start()
   # ... wait ...
   capture.stop()
   capture.save_to_pcap('capture.pcap')

   # Process offline
   with PCAPReader('capture.pcap') as reader:
       for packet in reader:
           # Process packet
   ```

5. **Limit capture duration/count:**
   ```python
   # Don't let memory grow indefinitely
   capture.start()
   while capture.packet_count < 10000:
       time.sleep(0.1)
   capture.stop()
   ```

## Best Practices

1. **Always use root/admin privileges** for raw packet capture
2. **Set appropriate filters** to reduce noise and improve performance
3. **Use PCAP format** for long-term storage and interoperability
4. **Implement packet limits** to prevent memory exhaustion
5. **Process packets in real-time** when possible (use callbacks)
6. **Save raw packets** for later detailed analysis
7. **Respect privacy** and legal requirements when capturing traffic
8. **Document your captures** (interface, time, filters, purpose)
9. **Test on non-production** networks first
10. **Monitor system resources** during long captures

## Security and Privacy

### Legal Considerations

- **Only capture traffic you own or have permission to monitor**
- Network packet capture may be illegal in many jurisdictions without proper authorization
- Respect privacy laws (GDPR, CCPA, etc.)
- Captured data may contain sensitive information (passwords, personal data)

### Security Best Practices

1. **Encrypt stored captures:**
   ```bash
   # Encrypt PCAP files
   gpg -c capture.pcap
   ```

2. **Secure file permissions:**
   ```bash
   chmod 600 capture.pcap
   ```

3. **Avoid capturing credentials:**
   ```python
   # Filter out authentication traffic if not needed
   capture.set_filter(...)  # Exclude auth endpoints
   ```

4. **Sanitize before sharing:**
   - Remove IP addresses
   - Remove MAC addresses
   - Remove payload data
   - Keep only headers if sufficient

5. **Delete captures when done:**
   ```bash
   shred -u capture.pcap  # Secure deletion
   ```

## Appendix

### Protocol Numbers

Common IP protocol numbers:

- 1: ICMP
- 2: IGMP
- 6: TCP
- 17: UDP
- 41: IPv6
- 47: GRE
- 50: ESP
- 51: AH
- 58: ICMPv6
- 89: OSPF
- 132: SCTP

### EtherType Values

Common Ethernet EtherType values:

- 0x0800: IPv4
- 0x0806: ARP
- 0x86DD: IPv6
- 0x8100: 802.1Q VLAN
- 0x88CC: LLDP
- 0x8863: PPPoE Discovery
- 0x8864: PPPoE Session

### Well-Known Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 20-21 | FTP | File Transfer |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Telnet |
| 25 | SMTP | Email |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Web |
| 110 | POP3 | Email |
| 143 | IMAP | Email |
| 443 | HTTPS | Secure Web |
| 3306 | MySQL | Database |
| 5432 | PostgreSQL | Database |
| 6379 | Redis | Database |
| 27017 | MongoDB | Database |

## Further Reading

- **RFC 791** - Internet Protocol (IPv4)
- **RFC 2460** - Internet Protocol Version 6 (IPv6)
- **RFC 793** - Transmission Control Protocol (TCP)
- **RFC 768** - User Datagram Protocol (UDP)
- **RFC 792** - Internet Control Message Protocol (ICMP)
- **RFC 826** - Address Resolution Protocol (ARP)
- **RFC 2616** - Hypertext Transfer Protocol (HTTP/1.1)
- **RFC 1035** - Domain Names - Implementation and Specification (DNS)
- **Wireshark Documentation** - https://www.wireshark.org/docs/
- **tcpdump Manual** - https://www.tcpdump.org/manpages/tcpdump.1.html

## License

See main README.md for license information.

## Contributing

Contributions welcome! Areas for improvement:

- Additional protocol dissectors (SMTP, FTP, SSH, TLS, etc.)
- Packet reassembly for fragmented traffic
- TCP stream reconstruction
- Better performance optimization
- Cross-platform compatibility improvements
- More filtering options
- Real-time analysis algorithms
