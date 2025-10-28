#!/usr/bin/env python3
"""
Protocol Dissectors for Multi-Layer Packet Analysis
Parses Ethernet, IP, TCP, UDP, ICMP, HTTP, DNS and more
"""

import struct
import socket
from datetime import datetime

class EthernetFrame:
    """Parse Ethernet II frames"""

    ETHERTYPE = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x0842: 'Wake-on-LAN',
        0x86DD: 'IPv6',
        0x8100: '802.1Q VLAN',
        0x8863: 'PPPoE Discovery',
        0x8864: 'PPPoE Session'
    }

    @staticmethod
    def parse(data):
        """
        Parse Ethernet frame

        Frame structure:
        - Destination MAC (6 bytes)
        - Source MAC (6 bytes)
        - EtherType (2 bytes)
        - Payload (46-1500 bytes)
        - FCS (4 bytes, often stripped by NIC)
        """
        if len(data) < 14:
            return None

        # Unpack destination MAC, source MAC, ethertype
        dst_mac = data[0:6]
        src_mac = data[6:12]
        ethertype = struct.unpack('!H', data[12:14])[0]

        return {
            'dst_mac': ':'.join(f'{b:02x}' for b in dst_mac),
            'src_mac': ':'.join(f'{b:02x}' for b in src_mac),
            'ethertype': ethertype,
            'ethertype_name': EthernetFrame.ETHERTYPE.get(ethertype, f'Unknown (0x{ethertype:04x})'),
            'data': data[14:]  # Remaining payload
        }


class IPPacket:
    """Parse IPv4 and IPv6 packets"""

    PROTOCOL = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP'
    }

    @staticmethod
    def parse(data):
        """Parse IP packet (auto-detect v4 or v6)"""
        if len(data) < 1:
            return None

        version = (data[0] >> 4) & 0xF

        if version == 4:
            return IPPacket.parse_ipv4(data)
        elif version == 6:
            return IPPacket.parse_ipv6(data)
        else:
            return None

    @staticmethod
    def parse_ipv4(data):
        """
        Parse IPv4 packet

        Header structure (20+ bytes):
        - Version + IHL (1 byte)
        - DSCP + ECN (1 byte)
        - Total Length (2 bytes)
        - Identification (2 bytes)
        - Flags + Fragment Offset (2 bytes)
        - TTL (1 byte)
        - Protocol (1 byte)
        - Header Checksum (2 bytes)
        - Source IP (4 bytes)
        - Destination IP (4 bytes)
        - Options (variable)
        """
        if len(data) < 20:
            return None

        # Parse header
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0xF
        ihl = version_ihl & 0xF
        header_length = ihl * 4

        if len(data) < header_length:
            return None

        dscp_ecn = data[1]
        dscp = (dscp_ecn >> 2) & 0x3F
        ecn = dscp_ecn & 0x03

        total_length, identification, flags_fragoffset, ttl, protocol, checksum = struct.unpack(
            '!HHBBH', data[2:12]
        )

        flags = (flags_fragoffset >> 13) & 0x07
        fragment_offset = flags_fragoffset & 0x1FFF

        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        # Extract options if present
        options = data[20:header_length] if header_length > 20 else b''

        return {
            'version': version,
            'ihl': ihl,
            'header_length': header_length,
            'dscp': dscp,
            'ecn': ecn,
            'total_length': total_length,
            'identification': identification,
            'flags': {
                'reserved': (flags >> 2) & 0x01,
                'df': (flags >> 1) & 0x01,  # Don't Fragment
                'mf': flags & 0x01  # More Fragments
            },
            'fragment_offset': fragment_offset,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': IPPacket.PROTOCOL.get(protocol, f'Unknown ({protocol})'),
            'checksum': checksum,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'options': options,
            'data': data[header_length:]
        }

    @staticmethod
    def parse_ipv6(data):
        """
        Parse IPv6 packet

        Header structure (40 bytes fixed):
        - Version + Traffic Class + Flow Label (4 bytes)
        - Payload Length (2 bytes)
        - Next Header (1 byte)
        - Hop Limit (1 byte)
        - Source Address (16 bytes)
        - Destination Address (16 bytes)
        """
        if len(data) < 40:
            return None

        # Parse fixed header
        version_tc_fl = struct.unpack('!I', data[0:4])[0]
        version = (version_tc_fl >> 28) & 0xF
        traffic_class = (version_tc_fl >> 20) & 0xFF
        flow_label = version_tc_fl & 0xFFFFF

        payload_length, next_header, hop_limit = struct.unpack('!HBB', data[4:8])

        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

        return {
            'version': version,
            'traffic_class': traffic_class,
            'flow_label': flow_label,
            'payload_length': payload_length,
            'next_header': next_header,
            'protocol': next_header,  # For compatibility
            'protocol_name': IPPacket.PROTOCOL.get(next_header, f'Unknown ({next_header})'),
            'hop_limit': hop_limit,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'data': data[40:]
        }


class TCPSegment:
    """Parse TCP segments"""

    FLAGS = {
        0x01: 'FIN',
        0x02: 'SYN',
        0x04: 'RST',
        0x08: 'PSH',
        0x10: 'ACK',
        0x20: 'URG',
        0x40: 'ECE',
        0x80: 'CWR'
    }

    @staticmethod
    def parse(data):
        """
        Parse TCP segment

        Header structure (20+ bytes):
        - Source Port (2 bytes)
        - Destination Port (2 bytes)
        - Sequence Number (4 bytes)
        - Acknowledgment Number (4 bytes)
        - Data Offset + Flags (2 bytes)
        - Window Size (2 bytes)
        - Checksum (2 bytes)
        - Urgent Pointer (2 bytes)
        - Options (variable)
        """
        if len(data) < 20:
            return None

        # Parse header
        src_port, dst_port, seq_num, ack_num, offset_flags, window, checksum, urgent = struct.unpack(
            '!HHIIHHH', data[:18]
        )

        # Data offset is in 4-byte words
        data_offset = (offset_flags >> 12) & 0xF
        header_length = data_offset * 4

        if len(data) < header_length:
            return None

        # Parse flags
        flags = offset_flags & 0x1FF
        flag_names = []
        for flag_bit, flag_name in TCPSegment.FLAGS.items():
            if flags & flag_bit:
                flag_names.append(flag_name)

        # Parse options if present
        options = data[20:header_length] if header_length > 20 else b''

        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'data_offset': data_offset,
            'header_length': header_length,
            'flags': flags,
            'flags_str': ','.join(flag_names) if flag_names else 'NONE',
            'window': window,
            'checksum': checksum,
            'urgent_pointer': urgent,
            'options': options,
            'data': data[header_length:],
            'payload_size': len(data) - header_length
        }


class UDPDatagram:
    """Parse UDP datagrams"""

    @staticmethod
    def parse(data):
        """
        Parse UDP datagram

        Header structure (8 bytes):
        - Source Port (2 bytes)
        - Destination Port (2 bytes)
        - Length (2 bytes)
        - Checksum (2 bytes)
        """
        if len(data) < 8:
            return None

        src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])

        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'checksum': checksum,
            'data': data[8:],
            'payload_size': length - 8
        }


class ICMPPacket:
    """Parse ICMP packets"""

    TYPE_NAMES = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        4: 'Source Quench',
        5: 'Redirect',
        8: 'Echo Request',
        9: 'Router Advertisement',
        10: 'Router Solicitation',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp',
        14: 'Timestamp Reply',
        15: 'Information Request',
        16: 'Information Reply',
        17: 'Address Mask Request',
        18: 'Address Mask Reply'
    }

    @staticmethod
    def parse(data):
        """
        Parse ICMP packet

        Header structure (8+ bytes):
        - Type (1 byte)
        - Code (1 byte)
        - Checksum (2 bytes)
        - Rest of Header (4 bytes, varies by type)
        """
        if len(data) < 8:
            return None

        icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
        rest_of_header = struct.unpack('!I', data[4:8])[0]

        return {
            'type': icmp_type,
            'type_name': ICMPPacket.TYPE_NAMES.get(icmp_type, f'Unknown ({icmp_type})'),
            'code': code,
            'checksum': checksum,
            'rest_of_header': rest_of_header,
            'data': data[8:]
        }


class HTTPParser:
    """Parse HTTP requests and responses"""

    @staticmethod
    def parse(data):
        """Parse HTTP data (request or response)"""
        if not data or len(data) < 10:
            return None

        try:
            # Try to decode as text
            text = data.decode('utf-8', errors='ignore')

            # Check if it looks like HTTP
            lines = text.split('\r\n')
            if not lines:
                return None

            first_line = lines[0]

            # Check for HTTP request
            if any(first_line.startswith(method) for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']):
                return HTTPParser.parse_request(text)
            # Check for HTTP response
            elif first_line.startswith('HTTP/'):
                return HTTPParser.parse_response(text)

        except Exception:
            pass

        return None

    @staticmethod
    def parse_request(text):
        """Parse HTTP request"""
        lines = text.split('\r\n')
        if not lines:
            return None

        # Parse request line
        parts = lines[0].split(' ')
        if len(parts) < 3:
            return None

        method = parts[0]
        path = parts[1]
        version = parts[2]

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Extract body
        body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ''

        return {
            'type': 'request',
            'method': method,
            'path': path,
            'version': version,
            'headers': headers,
            'body': body
        }

    @staticmethod
    def parse_response(text):
        """Parse HTTP response"""
        lines = text.split('\r\n')
        if not lines:
            return None

        # Parse status line
        parts = lines[0].split(' ', 2)
        if len(parts) < 3:
            return None

        version = parts[0]
        status_code = parts[1]
        status_text = parts[2]

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Extract body
        body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ''

        return {
            'type': 'response',
            'version': version,
            'status_code': int(status_code) if status_code.isdigit() else 0,
            'status_text': status_text,
            'headers': headers,
            'body': body
        }


class DNSParser:
    """Parse DNS packets"""

    QTYPE = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        255: 'ANY'
    }

    @staticmethod
    def parse(data):
        """
        Parse DNS packet

        Header structure (12 bytes):
        - Transaction ID (2 bytes)
        - Flags (2 bytes)
        - Questions (2 bytes)
        - Answer RRs (2 bytes)
        - Authority RRs (2 bytes)
        - Additional RRs (2 bytes)
        """
        if len(data) < 12:
            return None

        try:
            # Parse header
            transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack(
                '!HHHHHH', data[:12]
            )

            # Parse flags
            qr = (flags >> 15) & 0x01  # Query/Response
            opcode = (flags >> 11) & 0x0F
            aa = (flags >> 10) & 0x01  # Authoritative Answer
            tc = (flags >> 9) & 0x01  # Truncated
            rd = (flags >> 8) & 0x01  # Recursion Desired
            ra = (flags >> 7) & 0x01  # Recursion Available
            z = (flags >> 4) & 0x07  # Reserved
            rcode = flags & 0x0F  # Response Code

            result = {
                'transaction_id': transaction_id,
                'is_response': bool(qr),
                'opcode': opcode,
                'authoritative': bool(aa),
                'truncated': bool(tc),
                'recursion_desired': bool(rd),
                'recursion_available': bool(ra),
                'rcode': rcode,
                'questions': questions,
                'answer_rrs': answer_rrs,
                'authority_rrs': authority_rrs,
                'additional_rrs': additional_rrs,
                'queries': []
            }

            # Parse questions (simplified - full parsing is complex)
            offset = 12
            for _ in range(questions):
                query_name, offset = DNSParser.parse_domain_name(data, offset)
                if offset + 4 <= len(data):
                    qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
                    result['queries'].append({
                        'name': query_name,
                        'type': DNSParser.QTYPE.get(qtype, f'Unknown ({qtype})'),
                        'class': qclass
                    })
                    offset += 4

            return result

        except Exception:
            return None

    @staticmethod
    def parse_domain_name(data, offset):
        """Parse DNS domain name with compression support"""
        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 10
        jumps = 0

        while offset < len(data):
            length = data[offset]

            # Check for compression pointer
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack('!H', data[offset:offset + 2])[0]
                pointer &= 0x3FFF
                if not jumped:
                    original_offset = offset + 2
                jumped = True
                offset = pointer
                jumps += 1
                if jumps > max_jumps:
                    break
                continue

            # End of name
            if length == 0:
                offset += 1
                break

            # Regular label
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode('utf-8', errors='ignore'))
            offset += length

        if jumped:
            offset = original_offset

        return '.'.join(labels) if labels else '<root>', offset


class ARPPacket:
    """Parse ARP packets"""

    OPERATIONS = {
        1: 'Request',
        2: 'Reply',
        3: 'RARP Request',
        4: 'RARP Reply'
    }

    @staticmethod
    def parse(data):
        """
        Parse ARP packet

        Structure (28 bytes for Ethernet/IPv4):
        - Hardware Type (2 bytes)
        - Protocol Type (2 bytes)
        - Hardware Address Length (1 byte)
        - Protocol Address Length (1 byte)
        - Operation (2 bytes)
        - Sender Hardware Address (6 bytes for Ethernet)
        - Sender Protocol Address (4 bytes for IPv4)
        - Target Hardware Address (6 bytes)
        - Target Protocol Address (4 bytes)
        """
        if len(data) < 28:
            return None

        hw_type, proto_type, hw_len, proto_len, operation = struct.unpack('!HHBBH', data[:8])

        sender_hw = data[8:8 + hw_len]
        sender_proto = data[8 + hw_len:8 + hw_len + proto_len]
        target_hw = data[8 + hw_len + proto_len:8 + hw_len + proto_len + hw_len]
        target_proto = data[8 + hw_len + proto_len + hw_len:8 + hw_len + proto_len + hw_len + proto_len]

        return {
            'hw_type': hw_type,
            'proto_type': proto_type,
            'operation': operation,
            'operation_name': ARPPacket.OPERATIONS.get(operation, f'Unknown ({operation})'),
            'sender_mac': ':'.join(f'{b:02x}' for b in sender_hw),
            'sender_ip': socket.inet_ntoa(sender_proto) if proto_len == 4 else sender_proto.hex(),
            'target_mac': ':'.join(f'{b:02x}' for b in target_hw),
            'target_ip': socket.inet_ntoa(target_proto) if proto_len == 4 else target_proto.hex()
        }


def format_bytes(data, max_length=64):
    """
    Format bytes for display

    Args:
        data: Bytes to format
        max_length: Maximum bytes to display

    Returns:
        str: Formatted hex string
    """
    if not data:
        return '<empty>'

    display_data = data[:max_length]
    hex_str = ' '.join(f'{b:02x}' for b in display_data)

    if len(data) > max_length:
        hex_str += f' ... ({len(data) - max_length} more bytes)'

    return hex_str


def hexdump(data, length=16, offset=0):
    """
    Generate hexdump output

    Args:
        data: Bytes to dump
        length: Bytes per line
        offset: Starting offset

    Returns:
        str: Hexdump formatted string
    """
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'{offset + i:08x}  {hex_part:<{length * 3}}  {ascii_part}')
    return '\n'.join(result)


if __name__ == '__main__':
    # Test protocol parsers
    print("Protocol Dissectors Module")
    print("Available parsers:")
    print("  - EthernetFrame")
    print("  - IPPacket (IPv4/IPv6)")
    print("  - TCPSegment")
    print("  - UDPDatagram")
    print("  - ICMPPacket")
    print("  - HTTPParser")
    print("  - DNSParser")
    print("  - ARPPacket")
