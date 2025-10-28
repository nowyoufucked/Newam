#!/usr/bin/env python3
"""
Raw Packet Capture Module
Captures and records network packets at all layers (Ethernet, IP, TCP/UDP, Application)

Requires root/administrator privileges for raw socket access.
"""

import socket
import struct
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime
import json
import os

class PacketCapture:
    """
    Raw packet capture with multi-layer support
    Captures at Ethernet/IP/TCP/UDP/Application layers
    """

    def __init__(self, interface=None, promiscuous=False, buffer_size=65535):
        """
        Initialize packet capture

        Args:
            interface: Network interface to capture on (None = all interfaces)
            promiscuous: Enable promiscuous mode
            buffer_size: Socket buffer size in bytes
        """
        self.interface = interface
        self.promiscuous = promiscuous
        self.buffer_size = buffer_size
        self.running = False
        self.packet_count = 0
        self.packets = []
        self.capture_thread = None
        self.start_time = None
        self.statistics = defaultdict(int)
        self.packet_callbacks = []

        # Protocol counters
        self.protocol_stats = {
            'ethernet': 0,
            'ipv4': 0,
            'ipv6': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'https': 0,
            'dns': 0,
            'other': 0
        }

        # Layer-specific filters
        self.filters = {
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,  # 'TCP', 'UDP', 'ICMP'
            'port': None  # Capture specific port (src or dst)
        }

    def create_raw_socket(self):
        """
        Create raw socket for packet capture
        Requires root/admin privileges
        """
        try:
            if sys.platform == 'linux':
                # Linux: AF_PACKET, SOCK_RAW
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    sock.bind((self.interface, 0))
                if self.promiscuous:
                    # Enable promiscuous mode on Linux
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
            elif sys.platform == 'darwin':
                # macOS: AF_INET, SOCK_RAW, IPPROTO_IP
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                if self.interface:
                    sock.setsockopt(socket.SOL_SOCKET, 25, self.interface.encode())  # SO_BINDTODEVICE
            elif sys.platform == 'win32':
                # Windows: AF_INET, SOCK_RAW, IPPROTO_IP
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                raise OSError(f"Unsupported platform: {sys.platform}")

            sock.settimeout(1.0)  # 1 second timeout for clean shutdown
            return sock

        except PermissionError:
            print("[ERROR] Raw socket creation requires root/administrator privileges")
            print("Try running with: sudo python3 packet_capture.py")
            raise
        except Exception as e:
            print(f"[ERROR] Failed to create raw socket: {e}")
            raise

    def set_filter(self, **kwargs):
        """
        Set packet filters

        Args:
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            src_port: Source port filter
            dst_port: Destination port filter
            protocol: Protocol filter ('TCP', 'UDP', 'ICMP')
            port: Port filter (matches src or dst)
        """
        self.filters.update(kwargs)

    def add_callback(self, callback):
        """
        Add callback function to be called for each captured packet

        Args:
            callback: Function that takes packet dict as argument
        """
        self.packet_callbacks.append(callback)

    def matches_filter(self, packet):
        """Check if packet matches current filters"""
        if self.filters['src_ip'] and packet.get('ip', {}).get('src_ip') != self.filters['src_ip']:
            return False
        if self.filters['dst_ip'] and packet.get('ip', {}).get('dst_ip') != self.filters['dst_ip']:
            return False
        if self.filters['protocol'] and packet.get('ip', {}).get('protocol') != self.filters['protocol']:
            return False

        # Port filters
        transport = packet.get('tcp') or packet.get('udp')
        if transport:
            if self.filters['src_port'] and transport.get('src_port') != self.filters['src_port']:
                return False
            if self.filters['dst_port'] and transport.get('dst_port') != self.filters['dst_port']:
                return False
            if self.filters['port']:
                if transport.get('src_port') != self.filters['port'] and \
                   transport.get('dst_port') != self.filters['port']:
                    return False

        return True

    def capture_packet(self, raw_data):
        """
        Process captured raw packet data

        Args:
            raw_data: Raw bytes from socket

        Returns:
            dict: Parsed packet information
        """
        packet = {
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'size': len(raw_data),
            'raw': raw_data
        }

        try:
            # Start parsing from appropriate layer
            if sys.platform == 'linux':
                # Linux provides full Ethernet frame
                from protocol_dissectors import EthernetFrame
                eth_frame = EthernetFrame.parse(raw_data)
                packet['ethernet'] = eth_frame
                ip_data = eth_frame['data']
                self.protocol_stats['ethernet'] += 1
            else:
                # Windows/macOS start at IP layer
                ip_data = raw_data

            # Parse IP layer
            from protocol_dissectors import IPPacket
            ip_packet = IPPacket.parse(ip_data)
            if ip_packet:
                packet['ip'] = ip_packet

                if ip_packet['version'] == 4:
                    self.protocol_stats['ipv4'] += 1
                elif ip_packet['version'] == 6:
                    self.protocol_stats['ipv6'] += 1

                # Parse transport layer
                transport_data = ip_packet['data']

                if ip_packet['protocol'] == 'TCP':
                    from protocol_dissectors import TCPSegment
                    tcp_segment = TCPSegment.parse(transport_data)
                    packet['tcp'] = tcp_segment
                    self.protocol_stats['tcp'] += 1

                    # Identify application protocol
                    app_proto = self.identify_application_protocol(tcp_segment)
                    if app_proto:
                        packet['application_protocol'] = app_proto
                        self.protocol_stats[app_proto.lower()] += 1

                    # Parse application layer if HTTP
                    if app_proto in ['HTTP', 'HTTPS']:
                        from protocol_dissectors import HTTPParser
                        http_data = HTTPParser.parse(tcp_segment.get('data', b''))
                        if http_data:
                            packet['http'] = http_data

                elif ip_packet['protocol'] == 'UDP':
                    from protocol_dissectors import UDPDatagram
                    udp_datagram = UDPDatagram.parse(transport_data)
                    packet['udp'] = udp_datagram
                    self.protocol_stats['udp'] += 1

                    # Check for DNS
                    if udp_datagram['src_port'] == 53 or udp_datagram['dst_port'] == 53:
                        packet['application_protocol'] = 'DNS'
                        self.protocol_stats['dns'] += 1
                        from protocol_dissectors import DNSParser
                        dns_data = DNSParser.parse(udp_datagram.get('data', b''))
                        if dns_data:
                            packet['dns'] = dns_data

                elif ip_packet['protocol'] == 'ICMP':
                    from protocol_dissectors import ICMPPacket
                    icmp_packet = ICMPPacket.parse(transport_data)
                    packet['icmp'] = icmp_packet
                    self.protocol_stats['icmp'] += 1
                else:
                    self.protocol_stats['other'] += 1

            # Check filters
            if not self.matches_filter(packet):
                return None

            self.packet_count += 1
            self.packets.append(packet)

            # Call registered callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    print(f"[ERROR] Callback error: {e}")

            return packet

        except Exception as e:
            print(f"[ERROR] Packet parsing error: {e}")
            self.protocol_stats['other'] += 1
            return None

    def identify_application_protocol(self, tcp_segment):
        """
        Identify application layer protocol based on port

        Args:
            tcp_segment: Parsed TCP segment

        Returns:
            str: Protocol name or None
        """
        port = tcp_segment.get('dst_port', 0)

        common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT',
            27017: 'MongoDB'
        }

        return common_ports.get(port)

    def capture_loop(self):
        """Main packet capture loop"""
        try:
            sock = self.create_raw_socket()
            print(f"[+] Packet capture started on {self.interface or 'all interfaces'}")
            print(f"[+] Promiscuous mode: {self.promiscuous}")
            print(f"[+] Press Ctrl+C to stop")

            while self.running:
                try:
                    raw_data, addr = sock.recvfrom(self.buffer_size)
                    self.capture_packet(raw_data)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] Capture error: {e}")

            # Cleanup
            if sys.platform == 'win32':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            print(f"\n[+] Capture stopped. Total packets: {self.packet_count}")

        except Exception as e:
            print(f"[ERROR] Capture loop error: {e}")
            self.running = False

    def start(self):
        """Start packet capture in background thread"""
        if self.running:
            print("[!] Capture already running")
            return

        self.running = True
        self.start_time = time.time()
        self.capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
        self.capture_thread.start()

    def stop(self):
        """Stop packet capture"""
        if not self.running:
            print("[!] Capture not running")
            return

        print("\n[+] Stopping capture...")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=3)

    def get_statistics(self):
        """Get capture statistics"""
        duration = time.time() - self.start_time if self.start_time else 0
        return {
            'total_packets': self.packet_count,
            'duration': duration,
            'packets_per_second': self.packet_count / duration if duration > 0 else 0,
            'protocol_stats': dict(self.protocol_stats),
            'total_bytes': sum(p['size'] for p in self.packets),
            'filter_active': any(v is not None for v in self.filters.values())
        }

    def save_to_json(self, filename):
        """
        Save captured packets to JSON file

        Args:
            filename: Output filename
        """
        try:
            # Convert packets to JSON-serializable format
            export_packets = []
            for packet in self.packets:
                export_packet = packet.copy()
                # Remove raw bytes (not JSON serializable)
                if 'raw' in export_packet:
                    del export_packet['raw']
                # Convert any remaining bytes to hex
                export_packet = self._convert_bytes_to_hex(export_packet)
                export_packets.append(export_packet)

            data = {
                'capture_info': {
                    'start_time': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                    'interface': self.interface,
                    'promiscuous': self.promiscuous,
                    'filters': self.filters
                },
                'statistics': self.get_statistics(),
                'packets': export_packets
            }

            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)

            print(f"[+] Saved {len(export_packets)} packets to {filename}")

        except Exception as e:
            print(f"[ERROR] Failed to save JSON: {e}")

    def _convert_bytes_to_hex(self, obj):
        """Recursively convert bytes to hex strings for JSON serialization"""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, dict):
            return {k: self._convert_bytes_to_hex(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_bytes_to_hex(item) for item in obj]
        else:
            return obj

    def save_to_pcap(self, filename):
        """
        Save captured packets to PCAP file format

        Args:
            filename: Output PCAP filename
        """
        try:
            from pcap_writer import PCAPWriter
            writer = PCAPWriter(filename)

            for packet in self.packets:
                writer.write_packet(
                    packet['raw'],
                    timestamp=packet['timestamp']
                )

            writer.close()
            print(f"[+] Saved {len(self.packets)} packets to {filename}")

        except ImportError:
            print("[ERROR] PCAP writer module not available")
        except Exception as e:
            print(f"[ERROR] Failed to save PCAP: {e}")

    def print_packet_summary(self, packet):
        """
        Print a summary of captured packet

        Args:
            packet: Parsed packet dict
        """
        timestamp = datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S.%f')[:-3]

        # Build summary string
        parts = [f"[{timestamp}]"]

        if 'ethernet' in packet:
            eth = packet['ethernet']
            parts.append(f"ETH {eth['src_mac']} → {eth['dst_mac']}")

        if 'ip' in packet:
            ip = packet['ip']
            parts.append(f"IP {ip['src_ip']} → {ip['dst_ip']}")

        if 'tcp' in packet:
            tcp = packet['tcp']
            flags = tcp.get('flags_str', '')
            parts.append(f"TCP {tcp['src_port']} → {tcp['dst_port']} [{flags}]")
            if 'application_protocol' in packet:
                parts.append(f"({packet['application_protocol']})")

        elif 'udp' in packet:
            udp = packet['udp']
            parts.append(f"UDP {udp['src_port']} → {udp['dst_port']}")
            if 'application_protocol' in packet:
                parts.append(f"({packet['application_protocol']})")

        elif 'icmp' in packet:
            icmp = packet['icmp']
            parts.append(f"ICMP type={icmp['type']} code={icmp['code']}")

        parts.append(f"len={packet['size']}")

        print(" ".join(parts))


def main():
    """Example usage of packet capture"""
    import argparse

    parser = argparse.ArgumentParser(description='Raw packet capture at all network layers')
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-p', '--promiscuous', action='store_true', help='Enable promiscuous mode')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-o', '--output', help='Output file (JSON or PCAP)')
    parser.add_argument('-f', '--filter-port', type=int, help='Filter by port')
    parser.add_argument('--filter-ip', help='Filter by IP address')
    parser.add_argument('--filter-protocol', choices=['TCP', 'UDP', 'ICMP'], help='Filter by protocol')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Check for root privileges
    if os.geteuid() != 0 and sys.platform != 'win32':
        print("[ERROR] This script requires root privileges")
        print("Run with: sudo python3 packet_capture.py")
        sys.exit(1)

    # Create capture instance
    capture = PacketCapture(
        interface=args.interface,
        promiscuous=args.promiscuous
    )

    # Set filters
    if args.filter_port:
        capture.set_filter(port=args.filter_port)
    if args.filter_ip:
        capture.set_filter(src_ip=args.filter_ip)
    if args.filter_protocol:
        capture.set_filter(protocol=args.filter_protocol)

    # Add callback for verbose output
    if args.verbose:
        capture.add_callback(capture.print_packet_summary)

    # Start capture
    try:
        capture.start()

        # Capture specified number of packets or until Ctrl+C
        if args.count:
            while capture.packet_count < args.count and capture.running:
                time.sleep(0.1)
            capture.stop()
        else:
            # Run until Ctrl+C
            while capture.running:
                time.sleep(1)
                # Print statistics every 10 seconds
                if capture.packet_count % 100 == 0 and capture.packet_count > 0:
                    stats = capture.get_statistics()
                    print(f"\r[Stats] Packets: {stats['total_packets']}, "
                          f"Rate: {stats['packets_per_second']:.1f} pps", end='')

    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
        capture.stop()

    # Print final statistics
    stats = capture.get_statistics()
    print("\n\n=== Capture Statistics ===")
    print(f"Total Packets: {stats['total_packets']}")
    print(f"Duration: {stats['duration']:.2f} seconds")
    print(f"Rate: {stats['packets_per_second']:.2f} packets/second")
    print(f"Total Bytes: {stats['total_bytes']:,}")
    print("\nProtocol Distribution:")
    for proto, count in sorted(stats['protocol_stats'].items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
            print(f"  {proto.upper()}: {count} ({percentage:.1f}%)")

    # Save output
    if args.output:
        if args.output.endswith('.pcap'):
            capture.save_to_pcap(args.output)
        else:
            capture.save_to_json(args.output)


if __name__ == '__main__':
    main()
