"""Illustrative data for the firewall page (shown with a "Sample data" label)."""
import random
from datetime import timedelta

from django.utils import timezone

HEALTH = ["ok", "warn", "crit"]


def _rng(name):
    return random.Random(name)


def firewall():
    r = _rng("fg01")
    # 24 hours in 15-minute steps; x labels every 4 hours
    steps = [f"{(i * 15) // 60:02d}:{(i * 15) % 60:02d}" for i in range(96)]

    def wave(base, amp, n=96):
        return [round(base + amp * r.uniform(-1, 1)) for _ in range(n)]

    def spark(base, amp, n=40):
        # gentle mean-reverting walk with a few small peaks, like the design's sparklines
        v, out = base, []
        for i in range(n):
            v += (base - v) * 0.35 + amp * r.uniform(-0.45, 0.45)
            peak = amp * 0.9 if r.random() < 0.08 else 0
            out.append(round(v + peak, 1))
        return out

    ifaces = [("port1", "WAN1", "Up", "WAN", 680, 520, 68), ("port2", "WAN2", "Up", "WAN", 450, 320, 45),
              ("port3", "LAN", "Up", "LAN", 220, 180, 32), ("port4", "DMZ", "Up", "LAN", 120, 95, 18),
              ("port5", "Internal", "Up", "LAN", 80, 60, 12), ("port6", "Guest", "Up", "LAN", 40, 28, 6),
              ("port7", "Management", "Up", "MGMT", 12, 8, 2), ("port8", "HA", "Up", "HA", 5, 4, 1),
              ("port9", "Unused", "Down", "-", 0, 0, 0), ("port10", "Unused", "Down", "-", 0, 0, 0)]
    now = timezone.localtime().replace(microsecond=0)
    sec = [("Critical", "Intrusion", "203.0.113.45", "10.10.20.15", "ET MALWARE C2 Communication Blocked"),
           ("Warning", "Web Filter", "192.168.1.25", "45.33.100.11", "Malicious URL Blocked (phishing)"),
           ("Warning", "IPS", "198.51.100.32", "10.10.10.8", "SQL Injection Attempt Blocked"),
           ("Info", "VPN", "-", "-", "User john logged in (SSL VPN)"),
           ("Warning", "AntiVirus", "203.0.113.88", "10.10.5.20", "Malware Download Blocked"),
           ("Info", "System", "-", "-", "Configuration change by admin")]
    offsets, acc = [], 4 * 60
    for _ in sec:
        offsets.append(acc)
        acc += r.randint(12 * 60, 45 * 60)
    return {
        "tags": [("shield", "Firewall", "ink"), ("grid", "Fortinet", "crit"), ("activity", "SNMP", "ok"),
                 ("terminal", "CLI", "ink"), ("code", "API", "ink"), ("globe", "Production", "info")],
        "info": [("Hostname", "FG-01"), ("IP Address", "10.10.1.254"), ("Management IP", "10.10.1.254"), ("Model", "FortiGate 100F"),
                 ("Serial Number", "FG100FTK21012345"), ("Firmware Version", "v7.4.3 (build 2654)"), ("HA Status", "Standalone"),
                 ("System Time", now.strftime("%Y-%m-%d %H:%M:%S") + " IST"),
                 ("Site / Location", "Mumbai (NSE) - DC-Rack-01"), ("Role", "Perimeter Firewall"), ("Contact", "network@wecrew.in"),
                 ("Description", "Main firewall for production network")],
        "ifaces": ifaces,
        "traffic": {"labels": steps, "unit": "", "yMax": 1000, "xLabelEvery": 16,
                    "series": [{"name": "Inbound (Mbps)", "color": "#2b4cff", "area": True, "areaOpacity": 0.12, "width": 1.4, "values": wave(620, 90)},
                               {"name": "Outbound (Mbps)", "color": "#ff5b2e", "area": True, "areaOpacity": 0.13, "width": 1.4, "values": wave(470, 60)}]},
        "sessions": {"labels": steps, "unit": "", "yMax": 200000, "xLabelEvery": 16,
                     "series": [{"name": "Active Sessions", "color": "#0f7a55", "area": True, "areaOpacity": 0.22, "width": 1.4,
                                 "values": wave(125000, 9000)}]},
        "security": [((now - timedelta(seconds=o)).strftime("%Y-%m-%d %H:%M:%S"),) + s for o, s in zip(offsets, sec)],
        "apps": [("YouTube", 320, 24, "#d92d20"), ("HTTPS", 280, 21, "#2b4cff"), ("Netflix", 180, 13, "#7a4fd6"), ("Microsoft", 120, 9, "#ff5b2e"),
                 ("Google", 100, 7, "#0f7a55"), ("Facebook", 80, 6, "#0e8a7a"), ("Teams", 60, 4, "#e08a00"), ("Others", 210, 15, "#a8a398")],
        # VPN status tiles: icon, label, value, note, note tone, tile tone
        "vpn": [("users", "SSL VPN Users", "24 / 200", "3", "ok", "info"),
                ("lock", "IPSec Tunnels", "2 / 4", "1 Down", "crit", "ok"),
                ("clock", "Uptime (VPN)", "86 days", "", "", "info")],
        "policies": [("file", "Total Policies", "120", "info"), ("shield", "Active Policies", "98", "ok"),
                     ("shield-alert", "Disabled Policies", "12", "crit"), ("bar", "Hit Count (24h)", "1.2M", "purple")],
        "resources": [("cpu", "CPU Usage", "18.4%", "info", "s-cpu2"), ("memory", "Memory Usage", "62.1%", "ok", "s-mem2"),
                      ("hdd", "Disk Usage", "46.2%", "crit", "s-disk")],
        "spark_cpu": {"values": spark(18, 5), "color": "#0f7a55"},
        "spark_mem": {"values": spark(62, 4), "color": "#2b4cff"},
        "spark_cpu2": {"values": spark(18, 5), "color": "#2b4cff"},
        "spark_mem2": {"values": spark(62, 4), "color": "#0f7a55"},
        "spark_disk": {"values": spark(46, 4), "color": "#ff5b2e"},
    }
