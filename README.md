# LNPS - Linux Network Packet Sniffer

A real-time network packet capture and security analysis tool with MITRE ATT&CK mapping. Sniffs raw traffic using Linux raw sockets, parses protocols (TCP, UDP, ICMP, ARP, DNS), detects threats, and generates professional HTML/JSON reports.

## Features

- **Live Capture** - Raw socket packet sniffing (requires root)
- **Demo Mode** - Simulated attack traffic for testing and demonstrations
- **Protocol Parsing** - Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS
- **8 Detection Rules** - Port scan, brute force, ARP spoof, DNS tunneling, ICMP flood, suspicious ports, insecure services, data exfiltration
- **MITRE ATT&CK Mapping** - 8 techniques across multiple tactics
- **Risk Scoring** - Per-alert and aggregate scoring with severity levels
- **Reports** - Professional HTML and JSON output with executive summary
- **Zero Dependencies** - Pure Python 3

## Quick Start

```bash
git clone https://github.com/Sh8rlock/LNPS.git
cd LNPS
python3 run_sniffer.py --demo
```

## Live Capture

```bash
sudo python3 run_sniffer.py --live -i eth0 -c 500
```

## Detection Rules

| Detection | MITRE ATT&CK | Severity |
|-----------|--------------|----------|
| Port Scanning (SYN scan) | T1046 | HIGH |
| SSH/RDP Brute Force | T1110 | CRITICAL |
| ARP Spoofing / Cache Poisoning | T1557.002 | CRITICAL |
| DNS Tunneling | T1071.004 | HIGH |
| ICMP Flood / DoS | T1498 | HIGH |
| Suspicious Ports (Metasploit, IRC) | T1571 | CRITICAL |
| Insecure Services (FTP, Telnet, HTTP) | T1040 | MEDIUM |
| Data Exfiltration (large transfers) | T1048 | HIGH |

## Project Structure

```
LNPS/
|-- run_sniffer.py          # Main entry point
|-- packet_sniffer.py       # Raw socket capture engine
|-- protocol_parser.py      # Protocol dissection (Eth, IP, TCP, UDP, ICMP, ARP, DNS)
|-- alert_engine.py         # Threat detection and MITRE mapping
|-- demo_traffic.py         # Simulated attack traffic generator
|-- report_generator.py     # HTML and JSON report output
```

## Demo Output

```
=== LNPS Scan Complete ===
Packets Captured: 899
Security Alerts: 20
Risk Score: 1375
MITRE Techniques: 8
Reports: lnps_report.html, lnps_report.json
```

## Requirements

- Python 3.6+
- Linux (raw sockets require root for live capture)
- No external dependencies

## Author

Larry Odeyemi - Cybersecurity & Cloud Infrastructure Engineer

## License

MIT License
