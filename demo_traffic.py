"""
LNPS - Demo Traffic Generator
Generates realistic simulated network packets for testing without root/live capture.
Includes: Normal traffic, port scans, brute force, ARP spoofing, DNS tunneling,
           ICMP flood, suspicious ports, insecure services, data exfiltration.
"""

import struct
import socket
import random


def build_ethernet(src_mac, dest_mac, proto=0x0800):
    """Build Ethernet frame header."""
    return struct.pack('! 6s 6s H',
                       bytes.fromhex(dest_mac.replace(':', '')),
                       bytes.fromhex(src_mac.replace(':', '')),
                       proto)


def build_ipv4(src_ip, dest_ip, protocol, payload_len, ttl=64):
    """Build IPv4 header (no options, 20 bytes)."""
    version_ihl = (4 << 4) | 5
    total_length = 20 + payload_len
    identification = random.randint(1, 65535)
    flags_fragment = 0x4000  # Don't Fragment
    header_checksum = 0
    src = socket.inet_aton(src_ip)
    dest = socket.inet_aton(dest_ip)

    header = struct.pack('!B B H H H B B H 4s 4s',
                         version_ihl, 0, total_length, identification,
                         flags_fragment, ttl, protocol, header_checksum,
                         src, dest)
    return header


def build_tcp(src_port, dest_port, flags_dict, payload=b'', seq=None, ack=None):
    """Build TCP header."""
    seq = seq or random.randint(100000, 999999)
    ack_num = ack or 0
    offset = 5
    flags = 0
    if flags_dict.get('FIN'): flags |= 0x01
    if flags_dict.get('SYN'): flags |= 0x02
    if flags_dict.get('RST'): flags |= 0x04
    if flags_dict.get('PSH'): flags |= 0x08
    if flags_dict.get('ACK'): flags |= 0x10
    if flags_dict.get('URG'): flags |= 0x20

    offset_flags = (offset << 12) | flags
    window = 65535
    checksum = 0
    urgent = 0

    header = struct.pack('!H H L L H H H H',
                         src_port, dest_port, seq, ack_num,
                         offset_flags, window, checksum, urgent)
    return header + payload


def build_udp(src_port, dest_port, payload=b''):
    """Build UDP header."""
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack('!H H H H', src_port, dest_port, length, checksum)
    return header + payload


def build_icmp(icmp_type=8, code=0, payload=b''):
    """Build ICMP header."""
    checksum = 0
    header = struct.pack('!B B H', icmp_type, code, checksum)
    return header + payload


def build_arp(opcode, sender_mac, sender_ip, target_mac, target_ip):
    """Build ARP packet."""
    hw_type = 1
    proto_type = 0x0800
    hw_size = 6
    proto_size = 4
    header = struct.pack('!H H B B H',
                         hw_type, proto_type, hw_size, proto_size, opcode)
    header += bytes.fromhex(sender_mac.replace(':', ''))
    header += socket.inet_aton(sender_ip)
    header += bytes.fromhex(target_mac.replace(':', ''))
    header += socket.inet_aton(target_ip)
    return header


def build_dns_query(txn_id=None):
    """Build minimal DNS query header."""
    txn_id = txn_id or random.randint(1, 65535)
    flags = 0x0100  # Standard query
    return struct.pack('!H H H H H H', txn_id, flags, 1, 0, 0, 0) + b'\x00' * 10


def generate_demo_packets():
    """Generate a full set of demo packets simulating realistic attack traffic."""
    packets = []

    attacker_ip = '192.168.1.100'
    attacker_mac = 'aa:bb:cc:dd:ee:01'
    server_ip = '10.0.0.50'
    server_mac = '11:22:33:44:55:66'
    gateway_ip = '192.168.1.1'
    gateway_mac = 'ff:ee:dd:cc:bb:aa'
    internal_ip = '192.168.1.25'
    internal_mac = 'aa:bb:cc:dd:ee:02'
    dns_server = '8.8.8.8'

    # === 1. Normal HTTP traffic (baseline) ===
    for i in range(5):
        sport = random.randint(49152, 65535)
        tcp_payload = build_tcp(sport, 80, {'SYN': True})
        ip_payload = build_ipv4(internal_ip, server_ip, 6, len(tcp_payload))
        eth = build_ethernet(internal_mac, server_mac)
        packets.append(eth + ip_payload + tcp_payload)

    # === 2. Normal HTTPS traffic ===
    for i in range(5):
        sport = random.randint(49152, 65535)
        tcp_payload = build_tcp(sport, 443, {'SYN': True, 'ACK': True})
        ip_payload = build_ipv4(internal_ip, server_ip, 6, len(tcp_payload))
        eth = build_ethernet(internal_mac, server_mac)
        packets.append(eth + ip_payload + tcp_payload)

    # === 3. Normal DNS queries ===
    for i in range(5):
        dns_payload = build_dns_query()
        udp_payload = build_udp(random.randint(49152, 65535), 53, dns_payload)
        ip_payload = build_ipv4(internal_ip, dns_server, 17, len(udp_payload))
        eth = build_ethernet(internal_mac, gateway_mac)
        packets.append(eth + ip_payload + udp_payload)

    # === 4. PORT SCAN - SYN scan on 15 ports ===
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 3306, 3389, 8080]
    for port in scan_ports:
        tcp_payload = build_tcp(random.randint(49152, 65535), port, {'SYN': True})
        ip_payload = build_ipv4(attacker_ip, server_ip, 6, len(tcp_payload))
        eth = build_ethernet(attacker_mac, server_mac)
        packets.append(eth + ip_payload + tcp_payload)

    # === 5. BRUTE FORCE - 8 SSH attempts ===
    for i in range(8):
        tcp_payload = build_tcp(random.randint(49152, 65535), 22, {'SYN': True})
        ip_payload = build_ipv4(attacker_ip, server_ip, 6, len(tcp_payload))
        eth = build_ethernet(attacker_mac, server_mac)
        packets.append(eth + ip_payload + tcp_payload)

    # === 6. BRUTE FORCE - 6 RDP attempts ===
    for i in range(6):
        tcp_payload = build_tcp(random.randint(49152, 65535), 3389, {'SYN': True})
        ip_payload = build_ipv4(attacker_ip, server_ip, 6, len(tcp_payload))
        eth = build_ethernet(attacker_mac, server_mac)
        packets.append(eth + ip_payload + tcp_payload)

    # === 7. ARP SPOOFING - Attacker impersonates gateway ===
    # Normal ARP from real gateway
    arp_normal = build_arp(2, gateway_mac, gateway_ip, 'ff:ff:ff:ff:ff:ff', '0.0.0.0')
    eth = build_ethernet(gateway_mac, 'ff:ff:ff:ff:ff:ff', 0x0806)
    packets.append(eth + arp_normal)

    # Spoofed ARP from attacker claiming to be gateway
    arp_spoof = build_arp(2, attacker_mac, gateway_ip, 'ff:ff:ff:ff:ff:ff', '0.0.0.0')
    eth = build_ethernet(attacker_mac, 'ff:ff:ff:ff:ff:ff', 0x0806)
    packets.append(eth + arp_spoof)

    # === 8. DNS TUNNELING - 20 rapid DNS queries ===
    for i in range(20):
        dns_payload = build_dns_query()
        udp_payload = build_udp(random.randint(49152, 65535), 53, dns_payload)
        ip_payload = build_ipv4(attacker_ip, dns_server, 17, len(udp_payload))
        eth = build_ethernet(attacker_mac, gateway_mac)
        packets.append(eth + ip_payload + udp_payload)

    # === 9. ICMP FLOOD - 25 pings ===
    for i in range(25):
        icmp_payload = build_icmp(8, 0, b'\x00' * 56)
        ip_payload = build_ipv4(attacker_ip, server_ip, 1, len(icmp_payload))
        eth = build_ethernet(attacker_mac, server_mac)
        packets.append(eth + ip_payload + icmp_payload)

    # === 10. SUSPICIOUS PORTS - Metasploit + IRC ===
    # Metasploit reverse shell on 4444
    tcp_payload = build_tcp(4444, random.randint(49152, 65535), {'PSH': True, 'ACK': True}, b'\x00' * 100)
    ip_payload = build_ipv4(server_ip, attacker_ip, 6, len(tcp_payload))
    eth = build_ethernet(server_mac, attacker_mac)
    packets.append(eth + ip_payload + tcp_payload)

    # IRC C2 channel on 6667
    tcp_payload = build_tcp(random.randint(49152, 65535), 6667, {'SYN': True})
    ip_payload = build_ipv4(attacker_ip, '203.0.113.50', 6, len(tcp_payload))
    eth = build_ethernet(attacker_mac, gateway_mac)
    packets.append(eth + ip_payload + tcp_payload)

    # Back Orifice on 31337
    tcp_payload = build_tcp(random.randint(49152, 65535), 31337, {'SYN': True})
    ip_payload = build_ipv4(attacker_ip, server_ip, 6, len(tcp_payload))
    eth = build_ethernet(attacker_mac, server_mac)
    packets.append(eth + ip_payload + tcp_payload)

    # === 11. INSECURE SERVICES - Telnet + FTP ===
    for port in [23, 21]:
        tcp_payload = build_tcp(random.randint(49152, 65535), port, {'SYN': True, 'ACK': True})
        ip_payload = build_ipv4(internal_ip, server_ip, 6, len(tcp_payload))
        eth = build_ethernet(internal_mac, server_mac)
        packets.append(eth + ip_payload + tcp_payload)

    # === 12. Normal ICMP (ping) ===
    for i in range(3):
        icmp_payload = build_icmp(8, 0, b'\x00' * 32)
        ip_payload = build_ipv4(internal_ip, server_ip, 1, len(icmp_payload))
        eth = build_ethernet(internal_mac, server_mac)
        packets.append(eth + ip_payload + icmp_payload)

    # === 13. DATA EXFILTRATION - Large outbound transfer ===
    chunk_size = 1400
    total_chunks = 800  # ~1.1 MB
    for i in range(total_chunks):
        payload = b'\x41' * chunk_size
        tcp_payload = build_tcp(random.randint(49152, 65535), 443, {'PSH': True, 'ACK': True}, payload)
        ip_payload = build_ipv4(attacker_ip, '203.0.113.100', 6, len(tcp_payload))
        eth = build_ethernet(attacker_mac, gateway_mac)
        packets.append(eth + ip_payload + tcp_payload)

    return packets

