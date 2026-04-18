#!/usr/bin/env python3
"""
LNPS - Linux Network Packet Sniffer
Main entry point. Supports live capture (requires root) and demo mode.

Usage:
    sudo python3 run_sniffer.py --live [-i eth0] [-c 100]
    python3 run_sniffer.py --demo
"""

import argparse
import sys
import time
from packet_sniffer import PacketSniffer
from alert_engine import AlertEngine
from report_generator import ReportGenerator
from demo_traffic import generate_demo_packets


BANNER = r"""
  _     _   _ ____  ____
 | |   | \ | |  _ \/ ___|
 | |   |  \| | |_) \___ \
 | |___| |\  |  __/ ___) |
 |_____|_| \_|_|   |____/

 Linux Network Packet Sniffer v1.0.0
 Author: Larry Odeyemi
 ─────────────────────────────────────
"""


def main():
    parser = argparse.ArgumentParser(
        description='LNPS - Linux Network Packet Sniffer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 run_sniffer.py --live              # Capture on all interfaces
  sudo python3 run_sniffer.py --live -i eth0       # Capture on eth0 only
  sudo python3 run_sniffer.py --live -c 200        # Capture 200 packets
  python3 run_sniffer.py --demo                    # Run with simulated traffic
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--live', action='store_true', help='Live packet capture (requires root/sudo)')
    mode.add_argument('--demo', action='store_true', help='Demo mode with simulated attack traffic')

    parser.add_argument('-i', '--interface', default=None, help='Network interface to sniff (default: all)')
    parser.add_argument('-c', '--count', type=int, default=0, help='Max packets to capture (0 = unlimited)')
    parser.add_argument('-o', '--output', default='lnps_report', help='Output report filename (without extension)')
    parser.add_argument('--json-only', action='store_true', help='Generate JSON report only')
    parser.add_argument('--html-only', action='store_true', help='Generate HTML report only')

    args = parser.parse_args()

    print(BANNER)

    # Initialize sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        max_packets=args.count,
    )

    # Capture packets
    if args.live:
        print("[*] Mode: LIVE CAPTURE")
        print(f"[*] Interface: {args.interface or 'all'}")
        print(f"[*] Max packets: {args.count or 'unlimited'}")
        print("=" * 50)
        packets = sniffer.start_live_capture()
    else:
        print("[*] Mode: DEMO (simulated attack traffic)")
        print("[*] Generating realistic network packets...")
        print("=" * 50)
        demo_packets = generate_demo_packets()
        packets = sniffer.process_demo_traffic(demo_packets)

    if not packets:
        print("[!] No packets captured. Exiting.")
        sys.exit(1)

    stats = sniffer.get_stats()

    print(f"\n{'=' * 50}")
    print(f"[*] Capture Complete")
    print(f"    Packets: {stats['total']}")
    print(f"    TCP: {stats['tcp']}  |  UDP: {stats['udp']}  |  ICMP: {stats['icmp']}  |  ARP: {stats['arp']}")
    print(f"    DNS: {stats['dns']}  |  Other: {stats['other']}")
    print(f"    Bytes: {stats['bytes_captured']:,}")
    print(f"    Duration: {stats['duration']}s  |  Rate: {stats['pps']} pkt/s")

    # Run security analysis
    print(f"\n{'=' * 50}")
    print("[*] Running Security Analysis...")
    engine = AlertEngine()
    alerts = engine.analyze(packets)
    alert_summary = engine.get_summary()

    print(f"    Alerts: {alert_summary['total_alerts']}")
    print(f"    Risk Score: {alert_summary['total_risk_score']}")
    print(f"    MITRE Techniques: {len(alert_summary['mitre_techniques'])}")

    # Print severity breakdown
    sev = alert_summary.get('severity_counts', {})
    print(f"    CRITICAL: {sev.get('CRITICAL', 0)}  |  HIGH: {sev.get('HIGH', 0)}  |  MEDIUM: {sev.get('MEDIUM', 0)}  |  LOW: {sev.get('LOW', 0)}")

    # Print alerts
    if alerts:
        print(f"\n{'=' * 50}")
        print("[*] Security Alerts:")
        print(f"{'─' * 90}")
        for a in sorted(alerts, key=lambda x: x['score'], reverse=True):
            mitre = f" [{a['mitre_technique']}]" if a['mitre_technique'] else ''
            print(f"  [{a['severity']:8s}] {a['title']}{mitre}")
            print(f"           {a['description'][:100]}")
            print(f"{'─' * 90}")

    # Generate reports
    print(f"\n{'=' * 50}")
    print("[*] Generating Reports...")

    report_gen = ReportGenerator(packets, alerts, stats, alert_summary)

    if not args.json_only:
        html_path = report_gen.generate_html(f"{args.output}.html")
        print(f"    HTML Report: {html_path}")

    if not args.html_only:
        json_path = report_gen.generate_json(f"{args.output}.json")
        print(f"    JSON Report: {json_path}")

    print(f"\n{'=' * 50}")
    print("[*] LNPS analysis complete.")
    print(f"    Open {args.output}.html in a browser for the full report.")


if __name__ == '__main__':
    main()

