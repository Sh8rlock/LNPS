"""
LNPS - Security Alert Engine
Detects suspicious network activity patterns from parsed packets.
Categories: Port Scan, Brute Force, DNS Tunneling, ARP Spoofing,
            Cleartext Credentials, Suspicious Ports, ICMP Flood,
            Data Exfiltration, Insecure Services
"""

from collections import defaultdict
import time


class AlertEngine:
    """Analyzes captured packets for security threats."""

    SEVERITY_SCORES = {
        'CRITICAL': 100,
        'HIGH': 75,
        'MEDIUM': 50,
        'LOW': 25,
        'INFO': 10,
    }

    SUSPICIOUS_PORTS = {
        4444: ('Metasploit Default', 'CRITICAL'),
        5555: ('Common Backdoor', 'HIGH'),
        1234: ('Common Backdoor', 'HIGH'),
        31337: ('Back Orifice / Elite', 'CRITICAL'),
        6667: ('IRC (C2 Channel)', 'HIGH'),
        6697: ('IRC SSL (C2 Channel)', 'HIGH'),
        9001: ('Tor Default', 'MEDIUM'),
        9050: ('Tor SOCKS', 'MEDIUM'),
        1080: ('SOCKS Proxy', 'MEDIUM'),
        3128: ('Squid Proxy', 'MEDIUM'),
        8888: ('Common Backdoor', 'HIGH'),
    }

    INSECURE_SERVICES = {
        21: ('FTP', 'Cleartext file transfer'),
        23: ('Telnet', 'Cleartext remote access'),
        25: ('SMTP', 'Unencrypted email relay'),
        80: ('HTTP', 'Unencrypted web traffic'),
        110: ('POP3', 'Cleartext email retrieval'),
        143: ('IMAP', 'Cleartext email access'),
        161: ('SNMP', 'Community string exposure'),
        445: ('SMB', 'Lateral movement vector'),
        3306: ('MySQL', 'Database exposed'),
        5432: ('PostgreSQL', 'Database exposed'),
        6379: ('Redis', 'Unauthenticated by default'),
        27017: ('MongoDB', 'Unauthenticated by default'),
        5900: ('VNC', 'Remote desktop exposure'),
    }

    def __init__(self, thresholds=None):
        self.alerts = []
        self.seen_alerts = set()
        self.thresholds = thresholds or {
            'port_scan_threshold': 10,
            'brute_force_threshold': 5,
            'icmp_flood_threshold': 20,
            'dns_query_threshold': 15,
            'large_transfer_bytes': 1048576,  # 1 MB
        }
        # Tracking state
        self.syn_tracker = defaultdict(set)        # src_ip -> set of dest_ports
        self.auth_tracker = defaultdict(int)        # src_ip -> count of auth attempts
        self.dns_tracker = defaultdict(int)         # src_ip -> dns query count
        self.icmp_tracker = defaultdict(int)        # src_ip -> icmp count
        self.arp_table = {}                         # ip -> mac (for ARP spoof detection)
        self.transfer_tracker = defaultdict(int)    # src_ip -> bytes sent
        self.insecure_seen = set()                  # (src_ip, port) dedup

    def analyze(self, packets):
        """Run all detection rules against captured packets."""
        for pkt in packets:
            layers = pkt.get('layers', {})

            # ARP analysis
            if 'arp' in layers:
                self._check_arp_spoof(layers['arp'], pkt['timestamp'])

            ipv4 = layers.get('ipv4', {})
            src_ip = ipv4.get('src_ip', '')
            dest_ip = ipv4.get('dest_ip', '')

            # TCP analysis
            if 'tcp' in layers:
                tcp = layers['tcp']
                self._check_port_scan(src_ip, dest_ip, tcp, pkt['timestamp'])
                self._check_brute_force(src_ip, dest_ip, tcp, pkt['timestamp'])
                self._check_suspicious_port(src_ip, dest_ip, tcp['src_port'], tcp['dest_port'], pkt['timestamp'])
                self._check_insecure_service(src_ip, dest_ip, tcp['dest_port'], pkt['timestamp'])
                self._check_data_exfil(src_ip, tcp.get('payload', b''), pkt['timestamp'])

            # UDP analysis
            if 'udp' in layers:
                udp = layers['udp']
                self._check_suspicious_port(src_ip, dest_ip, udp['src_port'], udp['dest_port'], pkt['timestamp'])
                self._check_insecure_service(src_ip, dest_ip, udp['dest_port'], pkt['timestamp'])

            # DNS analysis
            if 'dns' in layers:
                self._check_dns_tunneling(src_ip, pkt['timestamp'])

            # ICMP analysis
            if 'icmp' in layers:
                self._check_icmp_flood(src_ip, dest_ip, pkt['timestamp'])

        return self.alerts

    def _add_alert(self, alert_key, category, severity, title, description, src_ip, dest_ip=None, mitre_id=None, mitre_name=None, timestamp=None):
        """Add alert if not already seen (deduplication)."""
        if alert_key in self.seen_alerts:
            return
        self.seen_alerts.add(alert_key)

        alert = {
            'id': len(self.alerts) + 1,
            'category': category,
            'severity': severity,
            'score': self.SEVERITY_SCORES.get(severity, 0),
            'title': title,
            'description': description,
            'src_ip': src_ip,
            'dest_ip': dest_ip or 'N/A',
            'mitre_technique': mitre_id,
            'mitre_name': mitre_name,
            'timestamp': timestamp or time.time(),
        }
        self.alerts.append(alert)

    def _check_port_scan(self, src_ip, dest_ip, tcp, timestamp):
        """Detect port scanning: single source hitting many destination ports."""
        if tcp['flags'].get('SYN') and not tcp['flags'].get('ACK'):
            self.syn_tracker[src_ip].add(tcp['dest_port'])
            count = len(self.syn_tracker[src_ip])
            if count >= self.thresholds['port_scan_threshold']:
                self._add_alert(
                    f"portscan_{src_ip}",
                    'Port Scan',
                    'HIGH',
                    f'Port Scan Detected from {src_ip}',
                    f'{src_ip} sent SYN packets to {count} unique ports. '
                    f'Ports targeted: {sorted(list(self.syn_tracker[src_ip]))[:20]}',
                    src_ip, dest_ip,
                    'T1046', 'Network Service Discovery',
                    timestamp
                )

    def _check_brute_force(self, src_ip, dest_ip, tcp, timestamp):
        """Detect brute force: repeated connections to auth ports (22, 3389, 21)."""
        auth_ports = {22, 3389, 21, 23, 5900}
        if tcp['dest_port'] in auth_ports and tcp['flags'].get('SYN') and not tcp['flags'].get('ACK'):
            self.auth_tracker[f"{src_ip}:{tcp['dest_port']}"] += 1
            count = self.auth_tracker[f"{src_ip}:{tcp['dest_port']}"]
            if count >= self.thresholds['brute_force_threshold']:
                service_names = {22: 'SSH', 3389: 'RDP', 21: 'FTP', 23: 'Telnet', 5900: 'VNC'}
                svc = service_names.get(tcp['dest_port'], str(tcp['dest_port']))
                self._add_alert(
                    f"bruteforce_{src_ip}_{tcp['dest_port']}",
                    'Brute Force',
                    'CRITICAL',
                    f'Brute Force Attack on {svc} from {src_ip}',
                    f'{src_ip} made {count} connection attempts to {dest_ip}:{tcp["dest_port"]} ({svc}). '
                    f'Possible credential stuffing or brute force attack.',
                    src_ip, dest_ip,
                    'T1110', 'Brute Force',
                    timestamp
                )

    def _check_suspicious_port(self, src_ip, dest_ip, src_port, dest_port, timestamp):
        """Detect traffic on known malicious ports."""
        for port in [src_port, dest_port]:
            if port in self.SUSPICIOUS_PORTS:
                name, severity = self.SUSPICIOUS_PORTS[port]
                self._add_alert(
                    f"suspport_{src_ip}_{port}",
                    'Suspicious Port',
                    severity,
                    f'Traffic on Suspicious Port {port} ({name})',
                    f'Communication detected between {src_ip} and {dest_ip} on port {port} ({name}). '
                    f'This port is commonly associated with malicious tools or C2 frameworks.',
                    src_ip, dest_ip,
                    'T1571', 'Non-Standard Port',
                    timestamp
                )

    def _check_insecure_service(self, src_ip, dest_ip, dest_port, timestamp):
        """Flag traffic to known insecure/cleartext services."""
        key = (src_ip, dest_port)
        if dest_port in self.INSECURE_SERVICES and key not in self.insecure_seen:
            self.insecure_seen.add(key)
            name, risk = self.INSECURE_SERVICES[dest_port]
            self._add_alert(
                f"insecure_{src_ip}_{dest_port}",
                'Insecure Service',
                'MEDIUM',
                f'Insecure Service Detected: {name} (port {dest_port})',
                f'{src_ip} connected to {dest_ip}:{dest_port} ({name}). Risk: {risk}. '
                f'Consider using encrypted alternatives.',
                src_ip, dest_ip,
                'T1040', 'Network Sniffing',
                timestamp
            )

    def _check_arp_spoof(self, arp, timestamp):
        """Detect ARP spoofing: IP mapped to multiple MACs."""
        ip = arp['sender_ip']
        mac = arp['sender_mac']

        if ip in self.arp_table and self.arp_table[ip] != mac:
            self._add_alert(
                f"arpspoof_{ip}",
                'ARP Spoofing',
                'CRITICAL',
                f'ARP Spoofing Detected for {ip}',
                f'IP {ip} was previously mapped to MAC {self.arp_table[ip]} '
                f'but is now claiming MAC {mac}. Possible ARP cache poisoning.',
                ip, None,
                'T1557.002', 'ARP Cache Poisoning',
                timestamp
            )
        self.arp_table[ip] = mac

    def _check_dns_tunneling(self, src_ip, timestamp):
        """Detect potential DNS tunneling: excessive DNS queries from one host."""
        self.dns_tracker[src_ip] += 1
        if self.dns_tracker[src_ip] >= self.thresholds['dns_query_threshold']:
            self._add_alert(
                f"dnstunnel_{src_ip}",
                'DNS Tunneling',
                'HIGH',
                f'Potential DNS Tunneling from {src_ip}',
                f'{src_ip} made {self.dns_tracker[src_ip]} DNS queries. '
                f'Excessive DNS traffic may indicate DNS tunneling for data exfiltration or C2.',
                src_ip, None,
                'T1071.004', 'DNS',
                timestamp
            )

    def _check_icmp_flood(self, src_ip, dest_ip, timestamp):
        """Detect ICMP flood: excessive pings from single source."""
        self.icmp_tracker[src_ip] += 1
        if self.icmp_tracker[src_ip] >= self.thresholds['icmp_flood_threshold']:
            self._add_alert(
                f"icmpflood_{src_ip}",
                'ICMP Flood',
                'HIGH',
                f'ICMP Flood Detected from {src_ip}',
                f'{src_ip} sent {self.icmp_tracker[src_ip]} ICMP packets. '
                f'Possible ping flood / DoS attack or network reconnaissance.',
                src_ip, dest_ip,
                'T1498', 'Network Denial of Service',
                timestamp
            )

    def _check_data_exfil(self, src_ip, payload, timestamp):
        """Detect potential data exfiltration: large outbound transfers."""
        if isinstance(payload, bytes):
            self.transfer_tracker[src_ip] += len(payload)
        if self.transfer_tracker[src_ip] >= self.thresholds['large_transfer_bytes']:
            mb = round(self.transfer_tracker[src_ip] / (1024 * 1024), 2)
            self._add_alert(
                f"exfil_{src_ip}",
                'Data Exfiltration',
                'HIGH',
                f'Large Data Transfer from {src_ip}',
                f'{src_ip} has transferred {mb} MB of data. '
                f'Possible data exfiltration or unauthorized file transfer.',
                src_ip, None,
                'T1048', 'Exfiltration Over Alternative Protocol',
                timestamp
            )

    def get_summary(self):
        """Return alert summary statistics."""
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        mitre_techniques = set()

        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
            category_counts[alert['category']] += 1
            if alert['mitre_technique']:
                mitre_techniques.add((alert['mitre_technique'], alert['mitre_name']))

        total_risk = sum(a['score'] for a in self.alerts)

        return {
            'total_alerts': len(self.alerts),
            'severity_counts': dict(severity_counts),
            'category_counts': dict(category_counts),
            'mitre_techniques': sorted(list(mitre_techniques)),
            'total_risk_score': total_risk,
        }

