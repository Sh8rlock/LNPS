"""
LNPS - Packet Sniffer Engine
Captures packets using raw sockets (live mode) or processes simulated traffic (demo mode).
Requires root/sudo for live capture.
"""

import time
import struct
import socket
from protocol_parser import (
    parse_ethernet, parse_ipv4, parse_tcp, parse_udp,
    parse_icmp, parse_arp, parse_dns
)


class PacketSniffer:
    """Core packet capture and processing engine."""

    def __init__(self, interface=None, max_packets=0, bpf_filter=None):
        self.interface = interface
        self.max_packets = max_packets
        self.bpf_filter = bpf_filter
        self.packets = []
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'dns': 0,
            'other': 0,
            'bytes_captured': 0,
            'start_time': None,
            'end_time': None,
        }

    def start_live_capture(self):
        """Start live packet capture using raw sockets (requires root)."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("[!] ERROR: Live capture requires root privileges.")
            print("[*] Run with: sudo python3 run_sniffer.py --live")
            print("[*] Or use demo mode: python3 run_sniffer.py --demo")
            return []
        except OSError as e:
            print(f"[!] ERROR: {e}")
            print("[*] Raw sockets require Linux. Use --demo on other platforms.")
            return []

        if self.interface:
            sock.bind((self.interface, 0))

        self.stats['start_time'] = time.time()
        count = 0

        print(f"[*] Sniffing on {'all interfaces' if not self.interface else self.interface}...")
        print(f"[*] Max packets: {'unlimited' if self.max_packets == 0 else self.max_packets}")
        print("[*] Press Ctrl+C to stop\n")

        try:
            while True:
                raw_data, addr = sock.recvfrom(65535)
                packet = self._process_packet(raw_data, time.time())
                if packet:
                    self.packets.append(packet)
                    self._print_packet_summary(packet)
                    count += 1

                if self.max_packets > 0 and count >= self.max_packets:
                    break

        except KeyboardInterrupt:
            print(f"\n[*] Capture stopped. {count} packets captured.")

        finally:
            sock.close()
            self.stats['end_time'] = time.time()

        return self.packets

    def process_demo_traffic(self, demo_packets):
        """Process pre-generated demo traffic for testing."""
        self.stats['start_time'] = time.time()

        for raw_data in demo_packets:
            packet = self._process_packet(raw_data, time.time())
            if packet:
                self.packets.append(packet)

        self.stats['end_time'] = time.time()
        return self.packets

    def _process_packet(self, raw_data, timestamp):
        """Parse raw bytes into structured packet dictionary."""
        if len(raw_data) < 14:
            return None

        self.stats['total'] += 1
        self.stats['bytes_captured'] += len(raw_data)

        packet = {
            'timestamp': timestamp,
            'raw_length': len(raw_data),
            'layers': {},
            'summary': ''
        }

        # Layer 2 - Ethernet
        eth = parse_ethernet(raw_data)
        packet['layers']['ethernet'] = eth

        # ARP
        if eth['protocol'] == 0x0806:
            if len(eth['payload']) >= 28:
                arp = parse_arp(eth['payload'])
                packet['layers']['arp'] = arp
                packet['summary'] = (
                    f"ARP {arp['opcode_name']}: "
                    f"{arp['sender_ip']} ({arp['sender_mac']}) -> "
                    f"{arp['target_ip']} ({arp['target_mac']})"
                )
                self.stats['arp'] += 1
                return packet

        # IPv4
        if eth['protocol'] == 0x0800:
            if len(eth['payload']) < 20:
                return packet
            ip = parse_ipv4(eth['payload'])
            packet['layers']['ipv4'] = ip

            # TCP
            if ip['protocol'] == 6 and len(ip['payload']) >= 20:
                tcp = parse_tcp(ip['payload'])
                packet['layers']['tcp'] = tcp
                self.stats['tcp'] += 1

                # DNS over TCP
                if tcp['src_port'] == 53 or tcp['dest_port'] == 53:
                    if len(tcp['payload']) >= 12:
                        dns = parse_dns(tcp['payload'])
                        if dns:
                            packet['layers']['dns'] = dns
                            self.stats['dns'] += 1

                service_tag = f" ({tcp['service']})" if tcp['service'] else ''
                packet['summary'] = (
                    f"TCP {ip['src_ip']}:{tcp['src_port']} -> "
                    f"{ip['dest_ip']}:{tcp['dest_port']} "
                    f"{tcp['flag_str']}{service_tag}"
                )

            # UDP
            elif ip['protocol'] == 17 and len(ip['payload']) >= 8:
                udp = parse_udp(ip['payload'])
                packet['layers']['udp'] = udp
                self.stats['udp'] += 1

                # DNS over UDP
                if udp['src_port'] == 53 or udp['dest_port'] == 53:
                    if len(udp['payload']) >= 12:
                        dns = parse_dns(udp['payload'])
                        if dns:
                            packet['layers']['dns'] = dns
                            self.stats['dns'] += 1

                service_tag = f" ({udp['service']})" if udp['service'] else ''
                packet['summary'] = (
                    f"UDP {ip['src_ip']}:{udp['src_port']} -> "
                    f"{ip['dest_ip']}:{udp['dest_port']}{service_tag}"
                )

            # ICMP
            elif ip['protocol'] == 1 and len(ip['payload']) >= 4:
                icmp = parse_icmp(ip['payload'])
                packet['layers']['icmp'] = icmp
                self.stats['icmp'] += 1
                packet['summary'] = (
                    f"ICMP {ip['src_ip']} -> {ip['dest_ip']} "
                    f"{icmp['type_name']}"
                )

            else:
                self.stats['other'] += 1
                packet['summary'] = (
                    f"{ip['protocol_name']} {ip['src_ip']} -> {ip['dest_ip']}"
                )

        return packet

    def _print_packet_summary(self, packet):
        """Print one-line packet summary to console."""
        ts = time.strftime('%H:%M:%S', time.localtime(packet['timestamp']))
        print(f"  [{ts}] {packet['summary']}")

    def get_stats(self):
        """Return capture statistics."""
        duration = 0
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']
        self.stats['duration'] = round(duration, 2)
        self.stats['pps'] = round(self.stats['total'] / max(duration, 0.01), 1)
        return self.stats

