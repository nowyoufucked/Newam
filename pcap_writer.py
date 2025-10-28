#!/usr/bin/env python3
"""
PCAP and PCAPNG File Format Writer
Writes captured packets in standard PCAP format compatible with Wireshark
"""

import struct
import time
from datetime import datetime


class PCAPWriter:
    """
    Write packets to PCAP file format
    Compatible with Wireshark, tcpdump, and other analysis tools
    """

    # PCAP global header constants
    MAGIC_NUMBER = 0xa1b2c3d4  # Standard PCAP
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE = 0  # GMT
    SIGFIGS = 0
    SNAPLEN = 65535  # Max packet length
    NETWORK = 1  # Ethernet

    # Link-layer header types
    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101  # Raw IP packets
    LINKTYPE_LINUX_SLL = 113  # Linux cooked capture

    def __init__(self, filename, linktype=LINKTYPE_ETHERNET, snaplen=65535):
        """
        Initialize PCAP writer

        Args:
            filename: Output PCAP file path
            linktype: Link-layer header type
            snaplen: Maximum packet length to capture
        """
        self.filename = filename
        self.linktype = linktype
        self.snaplen = snaplen
        self.file = None
        self.packet_count = 0

        self._write_global_header()

    def _write_global_header(self):
        """Write PCAP global header"""
        self.file = open(self.filename, 'wb')

        # Global header: 24 bytes
        # - Magic number (4 bytes)
        # - Version major (2 bytes)
        # - Version minor (2 bytes)
        # - Thiszone (4 bytes)
        # - Sigfigs (4 bytes)
        # - Snaplen (4 bytes)
        # - Network/Link-layer type (4 bytes)
        header = struct.pack(
            'IHHiIII',
            self.MAGIC_NUMBER,
            self.VERSION_MAJOR,
            self.VERSION_MINOR,
            self.THISZONE,
            self.SIGFIGS,
            self.snaplen,
            self.linktype
        )
        self.file.write(header)

    def write_packet(self, packet_data, timestamp=None):
        """
        Write packet to PCAP file

        Args:
            packet_data: Raw packet bytes
            timestamp: Packet timestamp (float seconds since epoch), default is current time
        """
        if not self.file:
            raise ValueError("PCAP file not open")

        if timestamp is None:
            timestamp = time.time()

        # Split timestamp into seconds and microseconds
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)

        # Truncate packet if exceeds snaplen
        captured_len = min(len(packet_data), self.snaplen)
        packet_data = packet_data[:captured_len]

        # Packet header: 16 bytes
        # - Timestamp seconds (4 bytes)
        # - Timestamp microseconds (4 bytes)
        # - Captured length (4 bytes)
        # - Original length (4 bytes)
        packet_header = struct.pack(
            'IIII',
            ts_sec,
            ts_usec,
            captured_len,
            len(packet_data)
        )

        self.file.write(packet_header)
        self.file.write(packet_data)
        self.packet_count += 1

    def close(self):
        """Close PCAP file"""
        if self.file:
            self.file.close()
            self.file = None
            print(f"[+] Wrote {self.packet_count} packets to {self.filename}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class PCAPNGWriter:
    """
    Write packets to PCAPNG file format (Next Generation)
    More flexible than PCAP, supports multiple interfaces and metadata
    """

    # Block types
    BLOCK_TYPE_SHB = 0x0A0D0D0A  # Section Header Block
    BLOCK_TYPE_IDB = 0x00000001  # Interface Description Block
    BLOCK_TYPE_EPB = 0x00000006  # Enhanced Packet Block
    BLOCK_TYPE_SPB = 0x00000003  # Simple Packet Block

    # Options
    OPT_ENDOFOPT = 0
    OPT_COMMENT = 1
    OPT_SHB_HARDWARE = 2
    OPT_SHB_OS = 3
    OPT_SHB_USERAPPL = 4
    OPT_IF_NAME = 2
    OPT_IF_DESCRIPTION = 3
    OPT_IF_TSRESOL = 9

    BYTE_ORDER_MAGIC = 0x1A2B3C4D

    def __init__(self, filename, application="Python Packet Capture"):
        """
        Initialize PCAPNG writer

        Args:
            filename: Output PCAPNG file path
            application: Application name for metadata
        """
        self.filename = filename
        self.application = application
        self.file = None
        self.packet_count = 0
        self.interfaces = []

        self._write_section_header()

    def _write_section_header(self):
        """Write PCAPNG Section Header Block"""
        self.file = open(self.filename, 'wb')

        # Section Header Block
        options = self._encode_option(self.OPT_SHB_USERAPPL, self.application.encode('utf-8'))
        options += self._encode_option(self.OPT_ENDOFOPT, b'')

        block_data = struct.pack(
            'II',
            self.BYTE_ORDER_MAGIC,
            1  # Major version
        ) + struct.pack('H', 0)  # Minor version
        block_data += struct.pack('Q', 0xFFFFFFFFFFFFFFFF)  # Section length (unknown)
        block_data += options

        self._write_block(self.BLOCK_TYPE_SHB, block_data)

    def add_interface(self, linktype=1, snaplen=65535, name="", description=""):
        """
        Add interface description

        Args:
            linktype: Link-layer type (1 = Ethernet)
            snaplen: Maximum packet length
            name: Interface name
            description: Interface description

        Returns:
            int: Interface ID
        """
        interface_id = len(self.interfaces)
        self.interfaces.append({
            'linktype': linktype,
            'snaplen': snaplen,
            'name': name,
            'description': description
        })

        # Write Interface Description Block
        options = b''
        if name:
            options += self._encode_option(self.OPT_IF_NAME, name.encode('utf-8'))
        if description:
            options += self._encode_option(self.OPT_IF_DESCRIPTION, description.encode('utf-8'))
        options += self._encode_option(self.OPT_ENDOFOPT, b'')

        block_data = struct.pack('HH', linktype, 0)  # LinkType + Reserved
        block_data += struct.pack('I', snaplen)
        block_data += options

        self._write_block(self.BLOCK_TYPE_IDB, block_data)

        return interface_id

    def write_packet(self, packet_data, interface_id=0, timestamp=None):
        """
        Write packet to PCAPNG file

        Args:
            packet_data: Raw packet bytes
            interface_id: Interface ID (from add_interface)
            timestamp: Packet timestamp (float seconds since epoch)
        """
        if not self.file:
            raise ValueError("PCAPNG file not open")

        if not self.interfaces:
            # Add default interface if none exists
            self.add_interface(name="default")

        if timestamp is None:
            timestamp = time.time()

        # Convert timestamp to 64-bit microseconds
        timestamp_high = int(timestamp)
        timestamp_low = int((timestamp - timestamp_high) * 1000000)

        # Enhanced Packet Block
        captured_len = len(packet_data)
        original_len = captured_len

        # Pad packet data to 4-byte boundary
        padded_data = packet_data + b'\x00' * ((4 - (captured_len % 4)) % 4)

        block_data = struct.pack(
            'IIII',
            interface_id,
            timestamp_high,
            timestamp_low,
            captured_len
        )
        block_data += struct.pack('I', original_len)
        block_data += padded_data
        block_data += self._encode_option(self.OPT_ENDOFOPT, b'')

        self._write_block(self.BLOCK_TYPE_EPB, block_data)
        self.packet_count += 1

    def _encode_option(self, option_code, option_value):
        """Encode PCAPNG option"""
        option_len = len(option_value)
        padded_len = option_len + ((4 - (option_len % 4)) % 4)
        padded_value = option_value + b'\x00' * (padded_len - option_len)
        return struct.pack('HH', option_code, option_len) + padded_value

    def _write_block(self, block_type, block_data):
        """Write PCAPNG block"""
        block_total_length = 12 + len(block_data)  # Type + Length + Data + Length
        header = struct.pack('II', block_type, block_total_length)
        footer = struct.pack('I', block_total_length)
        self.file.write(header + block_data + footer)

    def close(self):
        """Close PCAPNG file"""
        if self.file:
            self.file.close()
            self.file = None
            print(f"[+] Wrote {self.packet_count} packets to {self.filename}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class PCAPReader:
    """Read packets from PCAP file"""

    def __init__(self, filename):
        """
        Initialize PCAP reader

        Args:
            filename: PCAP file to read
        """
        self.filename = filename
        self.file = None
        self.linktype = None
        self.snaplen = None
        self.packet_count = 0

        self._read_global_header()

    def _read_global_header(self):
        """Read and parse PCAP global header"""
        self.file = open(self.filename, 'rb')

        # Read global header (24 bytes)
        header_data = self.file.read(24)
        if len(header_data) < 24:
            raise ValueError("Invalid PCAP file: header too short")

        magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            'IHHiIII', header_data
        )

        # Check magic number
        if magic not in [0xa1b2c3d4, 0xd4c3b2a1]:
            raise ValueError(f"Invalid PCAP magic number: 0x{magic:08x}")

        self.linktype = network
        self.snaplen = snaplen

        print(f"[+] PCAP file: {self.filename}")
        print(f"[+] Link type: {self.linktype}")
        print(f"[+] Snap length: {self.snaplen}")

    def read_packet(self):
        """
        Read next packet from PCAP file

        Returns:
            dict: Packet info with timestamp and data, or None if EOF
        """
        if not self.file:
            return None

        # Read packet header (16 bytes)
        header_data = self.file.read(16)
        if len(header_data) < 16:
            return None  # EOF

        ts_sec, ts_usec, captured_len, original_len = struct.unpack('IIII', header_data)

        # Read packet data
        packet_data = self.file.read(captured_len)
        if len(packet_data) < captured_len:
            return None  # Truncated

        self.packet_count += 1

        return {
            'timestamp': ts_sec + (ts_usec / 1000000.0),
            'datetime': datetime.fromtimestamp(ts_sec + (ts_usec / 1000000.0)),
            'captured_len': captured_len,
            'original_len': original_len,
            'data': packet_data
        }

    def read_all_packets(self):
        """
        Read all packets from PCAP file

        Returns:
            list: List of packet dicts
        """
        packets = []
        while True:
            packet = self.read_packet()
            if packet is None:
                break
            packets.append(packet)
        return packets

    def close(self):
        """Close PCAP file"""
        if self.file:
            self.file.close()
            self.file = None
            print(f"[+] Read {self.packet_count} packets from {self.filename}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    def __iter__(self):
        """Make reader iterable"""
        return self

    def __next__(self):
        """Iterator next"""
        packet = self.read_packet()
        if packet is None:
            raise StopIteration
        return packet


def convert_json_to_pcap(json_file, pcap_file):
    """
    Convert JSON capture to PCAP format

    Args:
        json_file: Input JSON file from packet_capture.py
        pcap_file: Output PCAP file
    """
    import json

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        packets = data.get('packets', [])

        with PCAPWriter(pcap_file) as writer:
            for packet in packets:
                # Get raw packet data (stored as hex string in JSON)
                if 'raw' in packet:
                    raw_data = bytes.fromhex(packet['raw'])
                    timestamp = packet.get('timestamp', time.time())
                    writer.write_packet(raw_data, timestamp)

        print(f"[+] Converted {len(packets)} packets from JSON to PCAP")

    except Exception as e:
        print(f"[ERROR] Conversion failed: {e}")


def main():
    """Example usage"""
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Write: python3 pcap_writer.py write <output.pcap>")
        print("  Read: python3 pcap_writer.py read <input.pcap>")
        print("  Convert: python3 pcap_writer.py convert <input.json> <output.pcap>")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'write' and len(sys.argv) >= 3:
        # Example: Write test packet
        output_file = sys.argv[2]

        with PCAPWriter(output_file) as writer:
            # Write a sample Ethernet frame (example)
            test_packet = b'\x00' * 14 + b'\x45\x00' + b'\x00' * 50  # Dummy packet
            writer.write_packet(test_packet)
            print(f"[+] Wrote test packet to {output_file}")

    elif command == 'read' and len(sys.argv) >= 3:
        # Read and display PCAP
        input_file = sys.argv[2]

        with PCAPReader(input_file) as reader:
            for i, packet in enumerate(reader, 1):
                print(f"Packet {i}:")
                print(f"  Timestamp: {packet['datetime']}")
                print(f"  Length: {packet['captured_len']} bytes")
                print(f"  Data: {packet['data'][:32].hex()}...")
                if i >= 10:
                    print("(showing first 10 packets)")
                    break

    elif command == 'convert' and len(sys.argv) >= 4:
        # Convert JSON to PCAP
        json_file = sys.argv[2]
        pcap_file = sys.argv[3]
        convert_json_to_pcap(json_file, pcap_file)

    else:
        print("[ERROR] Invalid command")
        sys.exit(1)


if __name__ == '__main__':
    main()
