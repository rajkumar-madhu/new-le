from urllib.parse import urlparse

from django.shortcuts import render

from core.access import require

from .. import nagios as svc
from .common import csv_response, matches, paginate, perms, query_without_page

HOST_STATES = [("up", "Up"), ("down", "Down"), ("unreachable", "Unreachable"), ("pending", "Pending")]
SERVICE_STATES = [("ok", "OK"), ("warning", "Warning"), ("critical", "Critical"), ("unknown", "Unknown"), ("pending", "Pending")]


@require("view")
def nagios_status(request):
    ctx = {**perms(request), "configured": svc.configured(), "error": "", "status": None}
    tab = request.GET.get("tab", "services")
    if tab not in ("hosts", "services"):
        tab = "services"
    ctx["tab"] = tab
    if ctx["configured"]:
        ctx["nagios_host"] = urlparse(svc.base_url()).netloc or svc.base_url()
        try:
            ctx["status"] = svc.fetch_status(use_cache=request.GET.get("refresh") != "1")
        except svc.NagiosError as e:
            ctx["error"] = str(e)
    st = ctx["status"] or {"hosts": [], "services": [], "query_time": None, "program": ""}
    summary = svc.summarize(st)
    q, state, only_problems = request.GET.get("q", ""), request.GET.get("state", ""), request.GET.get("problems") == "1"
    if tab == "hosts":
        rows = [h for h in st["hosts"] if matches(q, h["name"], h["output"]) and (not state or h["state"] == state)
                and (not only_problems or h["state"] != "up")]
    else:
        rows = [s for s in st["services"] if matches(q, s["host"], s["service"], s["output"])
                and (not state or s["state"] == state) and (not only_problems or s["state"] != "ok")]
    if request.GET.get("format") == "csv":
        if tab == "hosts":
            return csv_response("nagios-hosts.csv", ["host", "state", "output", "last_check", "last_state_change", "acknowledged", "downtime"],
                                [[h["name"], h["state"], h["output"], h["last_check"] or "", h["last_change"] or "",
                                  h["acknowledged"], h["downtime"]] for h in rows])
        return csv_response("nagios-services.csv", ["host", "service", "state", "output", "last_check", "last_state_change", "acknowledged", "downtime"],
                            [[s["host"], s["service"], s["state"], s["output"], s["last_check"] or "", s["last_change"] or "",
                              s["acknowledged"], s["downtime"]] for s in rows])
    hc, sc = summary["host_counts"], summary["service_counts"]
    ctx.update({
        "summary": summary, "page": paginate(request, rows, default=20), "q": q, "state": state,
        "only_problems": only_problems, "states": HOST_STATES if tab == "hosts" else SERVICE_STATES,
        "query": query_without_page(request, "refresh"), "filtered": bool(q or state or only_problems),
        "tab_query": query_without_page(request, "refresh", "tab", "state"),
        "host_donut": {"segments": [
            {"label": "Up", "value": hc["up"], "color": "#16a34a"}, {"label": "Down", "value": hc["down"], "color": "#dc2626"},
            {"label": "Unreachable", "value": hc["unreachable"], "color": "#f97316"},
            {"label": "Pending", "value": hc["pending"], "color": "#cbd5e1"}], "thickness": 12},
        "service_donut": {"segments": [
            {"label": "OK", "value": sc["ok"], "color": "#16a34a"}, {"label": "Warning", "value": sc["warning"], "color": "#f59e0b"},
            {"label": "Critical", "value": sc["critical"], "color": "#dc2626"}, {"label": "Unknown", "value": sc["unknown"], "color": "#94a3b8"},
            {"label": "Pending", "value": sc["pending"], "color": "#cbd5e1"}], "thickness": 12},
    })
    return render(request, "telemetry/nagios.html", ctx)
