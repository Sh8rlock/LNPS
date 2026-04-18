"""
LNPS - Protocol Parser
Parses raw packet bytes into structured protocol data.
Supports: Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS
"""

import struct
import socket


def parse_ethernet(raw_data):
    """Parse Ethernet frame header (14 bytes)."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    return {
        'dest_mac': format_mac(dest_mac),
        'src_mac': format_mac(src_mac),
        'protocol': proto,
        'protocol_name': get_eth_protocol_name(proto),
        'payload': raw_data[14:]
    }


def parse_ipv4(raw_data):
    """Parse IPv4 header (20+ bytes)."""
    version_ihl = raw_data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, checksum, src_ip, dest_ip = struct.unpack('! 8x B B H 4s 4s', raw_data[:20])
    total_length = struct.unpack('!H', raw_data[2:4])[0]

    flags_fragment = struct.unpack('!H', raw_data[6:8])[0]
    flags = (flags_fragment >> 13) & 0x7
    fragment_offset = flags_fragment & 0x1FFF

    return {
        'version': version,
        'header_length': ihl,
        'ttl': ttl,
        'protocol': proto,
        'protocol_name': get_ip_protocol_name(proto),
        'checksum': checksum,
        'src_ip': socket.inet_ntoa(src_ip),
        'dest_ip': socket.inet_ntoa(dest_ip),
        'total_length': total_length,
        'flags': flags,
        'fragment_offset': fragment_offset,
        'payload': raw_data[ihl:]
    }


def parse_tcp(raw_data):
    """Parse TCP header (20+ bytes)."""
    src_port, dest_port, seq, ack, offset_flags = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        'FIN': bool(offset_flags & 0x01),
        'SYN': bool(offset_flags & 0x02),
        'RST': bool(offset_flags & 0x04),
        'PSH': bool(offset_flags & 0x08),
        'ACK': bool(offset_flags & 0x10),
        'URG': bool(offset_flags & 0x20),
    }
    window_size = struct.unpack('!H', raw_data[14:16])[0]

    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'sequence': seq,
        'acknowledgment': ack,
        'header_length': offset,
        'flags': flags,
        'flag_str': get_tcp_flag_str(flags),
        'window_size': window_size,
        'service': identify_service(src_port, dest_port),
        'payload': raw_data[offset:]
    }


def parse_udp(raw_data):
    """Parse UDP header (8 bytes)."""
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', raw_data[:8])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'checksum': checksum,
        'service': identify_service(src_port, dest_port),
        'payload': raw_data[8:]
    }


def parse_icmp(raw_data):
    """Parse ICMP header (8 bytes)."""
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return {
        'type': icmp_type,
        'code': code,
        'checksum': checksum,
        'type_name': get_icmp_type_name(icmp_type),
        'payload': raw_data[4:]
    }


def parse_arp(raw_data):
    """Parse ARP header (28 bytes)."""
    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack('! H H B B H', raw_data[:8])
    sender_mac = raw_data[8:14]
    sender_ip = raw_data[14:18]
    target_mac = raw_data[18:24]
    target_ip = raw_data[24:28]

    return {
        'hw_type': hw_type,
        'protocol_type': proto_type,
        'opcode': opcode,
        'opcode_name': 'REQUEST' if opcode == 1 else 'REPLY' if opcode == 2 else f'UNKNOWN({opcode})',
        'sender_mac': format_mac(sender_mac),
        'sender_ip': socket.inet_ntoa(sender_ip),
        'target_mac': format_mac(target_mac),
        'target_ip': socket.inet_ntoa(target_ip)
    }


def parse_dns(raw_data):
    """Parse DNS header (basic)."""
    if len(raw_data) < 12:
        return None
    txn_id, flags, q_count, a_count, auth_count, add_count = struct.unpack('!H H H H H H', raw_data[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF

    return {
        'transaction_id': txn_id,
        'qr': 'RESPONSE' if qr else 'QUERY',
        'opcode': opcode,
        'rcode': rcode,
        'questions': q_count,
        'answers': a_count,
        'authority': auth_count,
        'additional': add_count
    }


# === Helper Functions ===

def format_mac(mac_bytes):
    """Format MAC address bytes to colon-separated hex string."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def get_eth_protocol_name(proto):
    """Map Ethernet protocol number to name."""
    protocols = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x86DD: 'IPv6',
        0x8100: 'VLAN',
    }
    return protocols.get(proto, f'Unknown(0x{proto:04x})')


def get_ip_protocol_name(proto):
    """Map IP protocol number to name."""
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
    }
    return protocols.get(proto, f'Unknown({proto})')


def get_tcp_flag_str(flags):
    """Return compact flag string like [SYN,ACK]."""
    active = [name for name, val in flags.items() if val]
    return f"[{','.join(active)}]" if active else "[]"


def get_icmp_type_name(icmp_type):
    """Map ICMP type to name."""
    types = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        5: 'Redirect',
        8: 'Echo Request',
        11: 'Time Exceeded',
    }
    return types.get(icmp_type, f'Type({icmp_type})')


def identify_service(src_port, dest_port):
    """Identify well-known service from port numbers."""
    services = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    }
    for port in [dest_port, src_port]:
        if port in services:
            return services[port]
    return None

