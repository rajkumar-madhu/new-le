import csv
from urllib.parse import urlparse

from django.conf import settings
from django.core.paginator import Paginator
from django.http import HttpResponse

from core import prometheus
from core.access import can


def per_page(request, default=20):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def paginate(request, items, default=20):
    return Paginator(items, per_page(request, default)).get_page(request.GET.get("page"))


def query_without_page(request, *drop):
    q = request.GET.copy()
    for k in ("page",) + drop:
        q.pop(k, None)
    return q


def perms(request):
    u = request.user
    return {"can_operate": can(u, "operate"), "can_admin": can(u, "admin")}


def prom_context():
    url = settings.PROMETHEUS_URL or ""
    host = urlparse(url).netloc or url
    return {"prom_configured": prometheus.configured(), "prom_host": host}


def csv_response(filename, header, rows):
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    w = csv.writer(resp)
    w.writerow(header)
    for r in rows:
        w.writerow([_cell(v) for v in r])
    return resp


def _cell(v):
    s = "" if v is None else str(v)
    # neutralise spreadsheet formulas
    return "'" + s if s[:1] in ("=", "+", "-", "@") and not _is_number(s) else s


def _is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


def matches(q, *fields):
    q = (q or "").strip().lower()
    return not q or any(q in str(f or "").lower() for f in fields)
