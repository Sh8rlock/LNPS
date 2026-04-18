"""
LNPS - Report Generator
Produces HTML and JSON reports from captured packets and security alerts.
"""

import json
import time
from collections import defaultdict


class ReportGenerator:
    """Generate professional security analysis reports."""

    def __init__(self, packets, alerts, stats, alert_summary):
        self.packets = packets
        self.alerts = alerts
        self.stats = stats
        self.alert_summary = alert_summary

    def generate_json(self, output_path='lnps_report.json'):
        """Generate JSON report."""
        report = {
            'report_metadata': {
                'tool': 'LNPS - Linux Network Packet Sniffer',
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'version': '1.0.0',
            },
            'capture_statistics': self.stats,
            'alert_summary': self.alert_summary,
            'alerts': self.alerts,
            'protocol_breakdown': self._get_protocol_breakdown(),
            'top_talkers': self._get_top_talkers(),
            'service_map': self._get_service_map(),
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return output_path

    def generate_html(self, output_path='lnps_report.html'):
        """Generate HTML report."""
        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#d97706',
            'LOW': '#2563eb',
            'INFO': '#6b7280',
        }

        protocol_breakdown = self._get_protocol_breakdown()
        top_talkers = self._get_top_talkers()
        service_map = self._get_service_map()

        # Build alert rows
        alert_rows = ''
        for a in sorted(self.alerts, key=lambda x: x['score'], reverse=True):
            color = severity_colors.get(a['severity'], '#6b7280')
            mitre = f"{a['mitre_technique']} - {a['mitre_name']}" if a['mitre_technique'] else 'N/A'
            alert_rows += f"""
            <tr>
                <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{a['severity']}</span></td>
                <td>{a['category']}</td>
                <td>{a['title']}</td>
                <td>{a['src_ip']}</td>
                <td>{a['dest_ip']}</td>
                <td><code>{mitre}</code></td>
                <td>{a['score']}</td>
            </tr>"""

        # Build protocol rows
        proto_rows = ''
        for proto, count in sorted(protocol_breakdown.items(), key=lambda x: x[1], reverse=True):
            pct = round(count / max(self.stats.get('total', 1), 1) * 100, 1)
            proto_rows += f"<tr><td>{proto}</td><td>{count}</td><td>{pct}%</td></tr>"

        # Build top talker rows
        talker_rows = ''
        for ip, count in top_talkers[:10]:
            talker_rows += f"<tr><td>{ip}</td><td>{count}</td></tr>"

        # Build service rows
        service_rows = ''
        for svc, count in sorted(service_map.items(), key=lambda x: x[1], reverse=True):
            service_rows += f"<tr><td>{svc}</td><td>{count}</td></tr>"

        # MITRE rows
        mitre_rows = ''
        for tid, tname in self.alert_summary.get('mitre_techniques', []):
            mitre_rows += f"<tr><td><code>{tid}</code></td><td>{tname}</td></tr>"

        # Severity summary
        sev_counts = self.alert_summary.get('severity_counts', {})
        risk_score = self.alert_summary.get('total_risk_score', 0)

        if risk_score >= 500:
            risk_color = '#dc2626'
            risk_label = 'CRITICAL'
        elif risk_score >= 300:
            risk_color = '#ea580c'
            risk_label = 'HIGH'
        elif risk_score >= 150:
            risk_color = '#d97706'
            risk_label = 'MEDIUM'
        else:
            risk_color = '#16a34a'
            risk_label = 'LOW'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LNPS Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; font-size: 28px; margin-bottom: 5px; }}
        h2 {{ color: #38bdf8; font-size: 20px; margin: 30px 0 15px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        .subtitle {{ color: #94a3b8; font-size: 14px; margin-bottom: 25px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e293b; border-radius: 8px; padding: 18px; text-align: center; border: 1px solid #334155; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #38bdf8; }}
        .stat-label {{ color: #94a3b8; font-size: 13px; margin-top: 5px; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 6px; font-weight: bold; font-size: 18px; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th {{ background: #1e293b; color: #38bdf8; padding: 10px 12px; text-align: left; font-size: 13px; text-transform: uppercase; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; font-size: 14px; }}
        tr:hover {{ background: #1e293b; }}
        code {{ background: #334155; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .three-col {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }}
        .section {{ background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; }}
        .footer {{ text-align: center; color: #64748b; margin-top: 40px; font-size: 12px; padding: 20px; }}
        @media (max-width: 768px) {{
            .two-col, .three-col {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>LNPS Security Report</h1>
    <p class="subtitle">Linux Network Packet Sniffer &mdash; Generated {time.strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{self.stats.get('total', 0)}</div>
            <div class="stat-label">Packets Captured</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{self.alert_summary.get('total_alerts', 0)}</div>
            <div class="stat-label">Security Alerts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:{risk_color}">{risk_score}</div>
            <div class="stat-label">Risk Score</div>
        </div>
        <div class="stat-card">
            <div class="risk-badge" style="background:{risk_color}">{risk_label}</div>
            <div class="stat-label">Threat Level</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(self.alert_summary.get('mitre_techniques', []))}</div>
            <div class="stat-label">MITRE Techniques</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{self.stats.get('bytes_captured', 0):,}</div>
            <div class="stat-label">Bytes Captured</div>
        </div>
    </div>

    <h2>Security Alerts</h2>
    <table>
        <thead><tr>
            <th>Severity</th><th>Category</th><th>Title</th>
            <th>Source IP</th><th>Dest IP</th><th>MITRE ATT&CK</th><th>Score</th>
        </tr></thead>
        <tbody>{alert_rows}</tbody>
    </table>

    <div class="three-col">
        <div class="section">
            <h2 style="margin-top:0;">Protocol Breakdown</h2>
            <table>
                <thead><tr><th>Protocol</th><th>Count</th><th>%</th></tr></thead>
                <tbody>{proto_rows}</tbody>
            </table>
        </div>
        <div class="section">
            <h2 style="margin-top:0;">Top Talkers</h2>
            <table>
                <thead><tr><th>IP Address</th><th>Packets</th></tr></thead>
                <tbody>{talker_rows}</tbody>
            </table>
        </div>
        <div class="section">
            <h2 style="margin-top:0;">Services Detected</h2>
            <table>
                <thead><tr><th>Service</th><th>Connections</th></tr></thead>
                <tbody>{service_rows}</tbody>
            </table>
        </div>
    </div>

    <h2>MITRE ATT&CK Coverage</h2>
    <div class="section">
        <table>
            <thead><tr><th>Technique ID</th><th>Technique Name</th></tr></thead>
            <tbody>{mitre_rows}</tbody>
        </table>
    </div>

    <h2>Severity Distribution</h2>
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value" style="color:#dc2626">{sev_counts.get('CRITICAL', 0)}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#ea580c">{sev_counts.get('HIGH', 0)}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#d97706">{sev_counts.get('MEDIUM', 0)}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#2563eb">{sev_counts.get('LOW', 0)}</div>
            <div class="stat-label">Low</div>
        </div>
    </div>

    <div class="footer">
        LNPS v1.0.0 &mdash; Linux Network Packet Sniffer &mdash; Larry Odeyemi
    </div>
</div>
</body>
</html>"""

        with open(output_path, 'w') as f:
            f.write(html)

        return output_path

    def _get_protocol_breakdown(self):
        """Count packets by protocol."""
        breakdown = defaultdict(int)
        for pkt in self.packets:
            layers = pkt.get('layers', {})
            if 'tcp' in layers:
                breakdown['TCP'] += 1
            elif 'udp' in layers:
                breakdown['UDP'] += 1
            elif 'icmp' in layers:
                breakdown['ICMP'] += 1
            elif 'arp' in layers:
                breakdown['ARP'] += 1
            else:
                breakdown['Other'] += 1
        return dict(breakdown)

    def _get_top_talkers(self):
        """Identify IPs generating most traffic."""
        talkers = defaultdict(int)
        for pkt in self.packets:
            ipv4 = pkt.get('layers', {}).get('ipv4', {})
            src = ipv4.get('src_ip')
            if src:
                talkers[src] += 1
        return sorted(talkers.items(), key=lambda x: x[1], reverse=True)

    def _get_service_map(self):
        """Map detected services and their connection counts."""
        services = defaultdict(int)
        for pkt in self.packets:
            layers = pkt.get('layers', {})
            for proto in ['tcp', 'udp']:
                if proto in layers and layers[proto].get('service'):
                    services[layers[proto]['service']] += 1
        return dict(services)

