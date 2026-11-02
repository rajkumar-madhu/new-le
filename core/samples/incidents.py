"""Illustrative data for the incidents page (shown with a "Sample data" label)."""
import random
from datetime import datetime, time, timedelta

from django.utils import timezone

HEALTH = ["ok", "warn", "crit"]


def _rng(name):
    return random.Random(name)


# id, title, priority, status, client, category, assignee, sla, sla tone, created (days before range end, hh:mm)
INCIDENTS = [
    ("INC-1287", "VPN connection issue", "High", "Open", "WeCrew", "Network", "Arul", "2h", "crit", (0, "09:24")),
    ("INC-1286", "Server CPU high", "Critical", "In Progress", "Finspot", "Server", "Priya", "1h", "crit", (0, "08:11")),
    ("INC-1285", "Email not working", "Medium", "Resolved", "Mirae", "Email", "Karthik", "—", "ok", (1, "17:32")),
    ("INC-1284", "Website down", "High", "Open", "Client A", "Application", "Unassigned", "3h", "crit", (1, "15:20")),
    ("INC-1283", "Switch port flap", "Low", "Closed", "Client B", "Network", "Ravi", "—", "ok", (1, "11:05")),
    ("INC-1282", "Database slow", "High", "In Progress", "WeCrew", "Database", "Divya", "45m", "warn", (1, "10:18")),
    ("INC-1281", "Domain not reachable", "Critical", "Open", "Client C", "DNS", "Unassigned", "4h", "crit", (2, "19:45")),
    ("INC-1280", "Printer not working", "Low", "Resolved", "Client D", "Hardware", "Mani", "—", "ok", (2, "16:22")),
    ("INC-1279", "New user access", "Medium", "Open", "WeCrew", "Access", "Unassigned", "1h", "warn", (2, "14:10")),
    ("INC-1278", "Software installation", "Low", "Closed", "Finspot", "Software", "Karthik", "—", "ok", (2, "11:05")),
    ("INC-1277", "Backup job failed", "Medium", "In Progress", "Mirae", "Server", "Priya", "2h", "warn", (3, "18:40")),
]

# pill tone + whether it carries a small leading dot (matches the design's priority / status chips)
PRIORITY_PILL = {"Critical": ("crit", True), "High": ("crit", False), "Medium": ("warn", True), "Low": ("ok", False)}
STATUS_PILL = {"Open": ("crit", False), "In Progress": ("warn", True), "On Hold": ("purple", True),
               "Resolved": ("ok", True), "Closed": ("mute", True)}

AVATAR_COLORS = {"Arul": "#2b4cff", "Priya": "#7a4fd6", "Karthik": "#0f7a55", "Ravi": "#9a4a06",
                 "Divya": "#cc4216", "Mani": "#3d3a35"}

CATEGORIES = [("Network", 32, "#2b4cff"), ("Server", 28, "#ff5b2e"), ("Application", 20, "#7a4fd6"),
              ("Access Management", 16, "#0f7a55"), ("Email", 12, "#e08a00"), ("Database", 8, "#d92d20"),
              ("Hardware", 8, "#a8a398")]

# Shape of the 15-day trend (created / resolved per day), with a little seeded jitter.
CREATED = [10, 8, 13, 9, 12, 23, 27, 20, 16, 19, 22, 24, 23, 28, 35]
RESOLVED = [7, 10, 8, 10, 13, 15, 15, 9, 11, 13, 13, 17, 20, 22, 22]


def _initials(name):
    return "".join(p[0] for p in name.split()[:2]).upper()


def incidents():
    r = _rng("incidents")
    end = timezone.localdate()
    days = [end - timedelta(days=14 - i) for i in range(15)]
    created = [max(2, v + r.choice([-1, 0, 0, 1])) for v in CREATED]
    resolved = [max(2, min(c - 1, v + r.choice([-1, 0, 0, 1]))) for v, c in zip(RESOLVED, created)]

    rows = []
    for (iid, title, prio, status, client, cat, who, sla, sla_tone, (ago, hm)) in INCIDENTS:
        h, m = (int(x) for x in hm.split(":"))
        ts = datetime.combine(end - timedelta(days=ago), time(h, m))
        p_tone, p_dot = PRIORITY_PILL[prio]
        s_tone, s_dot = STATUS_PILL[status]
        rows.append({
            "id": iid, "title": title, "priority": prio, "status": status, "client": client, "category": cat,
            "assignee": who, "unassigned": who == "Unassigned", "initials": _initials(who),
            "av_color": AVATAR_COLORS.get(who, "#6f6a61"),
            "created": ts.strftime("%b %-d, %H:%M"), "sla": sla, "sla_tone": sla_tone, "done": sla == "—",
            "p_tone": p_tone, "p_dot": p_dot, "s_tone": s_tone, "s_dot": s_dot,
        })

    def kpi(label, value, sub, glyph, tone, change, rotate=False):
        return {"label": label, "value": value, "sub": sub, "glyph": glyph, "tone": tone, "delta": change, "rotate": rotate}

    by_status = [{"label": "Open", "value": 48, "color": "#d92d20"}, {"label": "In Progress", "value": 24, "color": "#e08a00"},
                 {"label": "On Hold", "value": 12, "color": "#7a4fd6"}, {"label": "Resolved", "value": 76, "color": "#0f7a55"},
                 {"label": "Closed", "value": 36, "color": "#a8a398"}]
    sla_legend = [{"label": "Met", "value": 108, "color": "#0f7a55", "link": True},
                  {"label": "Breached", "value": 12, "color": "#d92d20"},
                  {"label": "At Risk", "value": 4, "color": "#e08a00"}]
    met = sla_legend[0]["value"]
    sla_total = sum(s["value"] for s in sla_legend)

    clients = ["WeCrew", "Finspot", "Mirae", "Client A", "Client B", "Client C", "Client D"]
    return {
        "range_label": f"{days[0].strftime('%b %-d, %Y')} - {days[-1].strftime('%b %-d, %Y')}",
        "clients": clients,
        "kpis": [
            kpi("Total Incidents", 124, "48 open, 76 resolved", "alert", "crit", -12),
            kpi("Critical", 8, "2 unassigned", "flame", "crit", 33),
            kpi("High", 16, "3 unassigned", "info", "orange", -11, rotate=True),
            kpi("Medium", 48, "12 unassigned", "info", "amber", -20, rotate=True),
            kpi("Low", 52, "5 unassigned", "info", "blue", -18),
        ],
        "rows": rows,
        "filters": [
            ("status", "Status", "All Statuses", list(STATUS_PILL)),
            ("priority", "Priority", "All Priorities", list(PRIORITY_PILL)),
            ("category", "Category", "All Categories", sorted({x[5] for x in INCIDENTS})),
            ("client", "Client", "All Clients", clients),
            ("assignee", "Assigned To", "All Users", sorted({x[6] for x in INCIDENTS})),
        ],
        "trend": {"labels": [d.strftime("%b %-d") for d in days],
                  "tipLabels": [d.strftime("%a, %b %-d") for d in days],
                  "unit": "", "yMax": 40, "yTicks": 4, "xLabelEvery": 2, "series": [
                      {"name": "Created", "color": "#2b4cff", "values": created, "area": True, "areaOpacity": 0.2, "width": 2},
                      {"name": "Resolved", "color": "#0f7a55", "values": resolved, "area": True, "areaOpacity": 0.2, "width": 2}]},
        "by_status": {"segments": by_status, "center": {"value": "124", "label": "Total"},
                      "thickness": 24},
        "sla": {"segments": [{"label": "Met", "value": met, "color": "#0f7a55"},
                             {"label": "Not met", "value": sla_total - met, "color": "#ebe5d9"}],
                "center": {"value": f"{round(met * 100 / sla_total)}%"}, "thickness": 18},
        "sla_legend": sla_legend,
        "categories": CATEGORIES,
        "cat_max": max(v for _, v, _ in CATEGORIES),
        "major": [(i, t, sub, st, STATUS_PILL[st][0]) for i, t, sub, st in [
            ("INC-1286", "Server CPU high", "2 hours ago • Finspot", "Open"),
            ("INC-1281", "Domain not reachable", "12 hours ago • Client C", "Open"),
            ("INC-1265", "Database outage", "1 day ago • WeCrew", "In Progress")]],
    }
