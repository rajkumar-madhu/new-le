"""CSV export and import of configuration items."""
import csv
import io
import json

from django.db import transaction

from . import services
from .forms import ENV_LOOKUP, MAX_IMPORT_ROWS, STATUS_LOOKUP, TYPE_LOOKUP, CIForm, link_queryset
from .models import ConfigurationItem

COLUMNS = ["name", "type", "status", "environment", "site", "owner", "business_domain", "ip_address", "vendor", "model",
           "serial", "asset_tag", "purchase_date", "warranty_end", "eol_date", "cost", "prometheus_instance",
           "url_checks", "domains", "description"]
FIELD_FOR = {"type": "ci_type"}
TEXT_FIELDS = ["owner", "business_domain", "ip_address", "vendor", "model", "serial", "asset_tag", "purchase_date",
               "warranty_end", "eol_date", "cost", "prometheus_instance", "description"]


FORMULA_CHARS = "=+-@\t\r"


def safe(value):
    """Neutralise spreadsheet formulas in exported text cells."""
    s = "" if value is None else str(value)
    if s and s[0] in FORMULA_CHARS:
        return "'" + s
    return s


def unsafe(value):
    """Undo safe() on import so an export -> import round trip keeps values such as "-backup" unchanged."""
    if len(value) > 1 and value[0] == "'" and value[1] in FORMULA_CHARS:
        return value[1:]
    return value


def write_cis(fileobj, cis):
    w = csv.writer(fileobj)
    w.writerow(COLUMNS)
    for c in cis:
        w.writerow([safe(x) for x in [
            c.name, c.ci_type, c.status, c.environment, c.site, c.owner, c.business_domain, c.ip_address or "", c.vendor,
            c.model, c.serial, c.asset_tag, c.purchase_date or "", c.warranty_end or "", c.eol_date or "",
            "" if c.cost is None else c.cost, c.prometheus_instance,
            ";".join(u.name for u in c.url_checks.all()), ";".join(d.hostname for d in c.domains.all()), c.description]])


def template_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLUMNS)
    w.writerow(["prod-app-01", "server", "active", "prod", "All Sites", "Platform team", "Trading", "10.10.1.21", "Dell",
                "PowerEdge R650", "SN12345", "AT-0001", "2024-04-01", "2027-03-31", "2030-03-31", "8500.00",
                "prod-app-01:9100", "", "", "Example row - replace before importing"])
    return buf.getvalue()


def _decode(raw):
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    raise ValueError("The file is not valid UTF-8 text.")


def _choice(lookup, value, default):
    v = (value or "").strip()
    if not v:
        return default, None
    hit = lookup.get(v) or lookup.get(v.lower()) or lookup.get(v.lower().replace(" ", "_"))
    return (hit, None) if hit else (None, v)


def _rows(reader, result):
    """(row number, row) pairs; a malformed CSV (e.g. a field over the csv module's size limit) becomes a row error
    instead of an exception."""
    it = enumerate(reader, start=2)
    while True:
        try:
            yield next(it)
        except StopIteration:
            return
        except csv.Error as e:
            result["errors"].append((reader.line_num, f"The file is not valid CSV: {e}."))
            return


def import_cis(uploaded, user, update_existing=True):
    """Validate every row with CIForm and save all of them, or none when any row fails.

    Returns {"created": n, "updated": n, "skipped": n, "errors": [(row number, message)], "items": [...]}.
    """
    from django.conf import settings
    from domainmonitor.models import Domain
    from urlchecker.models import UrlCheck

    result = {"created": 0, "updated": 0, "skipped": 0, "errors": [], "items": []}
    try:
        text = _decode(uploaded.read())
    except ValueError as e:
        result["errors"].append((0, str(e)))
        return result
    reader = csv.DictReader(io.StringIO(text))
    try:
        headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    except csv.Error as e:
        result["errors"].append((1, f"The file is not valid CSV: {e}."))
        return result
    if "name" not in headers:
        result["errors"].append((1, "The header row must include a 'name' column (download the template)."))
        return result
    reader.fieldnames = headers
    tenant = settings.LINKEDEYE_TENANT
    # only checks and domains on the user's sites can be linked (as in CIForm); others read as unknown
    checks = {u.name.lower(): u.pk for u in link_queryset(UrlCheck.objects.filter(tenant_key=tenant), user, "site")}
    doms = {d.hostname.lower(): d.pk for d in link_queryset(Domain.objects.filter(tenant_key=tenant), user, "site_key")}
    existing = {c.name.lower(): c for c in ConfigurationItem.objects.filter(tenant_key=tenant)}
    seen = set()
    forms_ok = []
    for n, row in _rows(reader, result):
        if n - 1 > MAX_IMPORT_ROWS:
            result["errors"].append((n, f"More than {MAX_IMPORT_ROWS} rows; split the file."))
            break
        row = {k: unsafe((v or "").strip()) for k, v in row.items() if k and not isinstance(v, list)}
        if not any(row.values()):
            continue
        name = row.get("name", "")
        key = name.lower()
        if key in seen:
            result["errors"].append((n, f"Duplicate name “{name}” in the file."))
            continue
        seen.add(key)
        inst = existing.get(key)
        if inst is not None and not update_existing:
            result["skipped"] += 1
            continue
        if inst is not None and not services.can_manage(user, "operate", inst.site):
            # never let an import rewrite (or move to another site) an item the user may not manage
            result["errors"].append((n, f"{name}: an item with this name exists on a site you cannot manage."))
            continue
        errs = []
        ci_type, bad = _choice(TYPE_LOOKUP, row.get("type"), inst.ci_type if inst else "server")
        if bad:
            errs.append(f"unknown type “{bad}”")
        status, bad = _choice(STATUS_LOOKUP, row.get("status"), inst.status if inst else "active")
        if bad:
            errs.append(f"unknown status “{bad}”")
        env, bad = _choice(ENV_LOOKUP, row.get("environment"), inst.environment if inst else "prod")
        if bad:
            errs.append(f"unknown environment “{bad}”")
        data = {"name": name, "ci_type": ci_type, "status": status, "environment": env,
                "site": row.get("site") or (inst.site if inst else "All Sites")}
        for f in TEXT_FIELDS:
            if f in row:
                data[f] = row[f]
            elif inst is not None:
                v = getattr(inst, f)
                data[f] = "" if v is None else str(v)
        data["attributes"] = json.dumps(inst.attributes) if inst is not None and inst.attributes else ""
        for col, lookup, attr, label in (("url_checks", checks, "url_checks", "URL check"), ("domains", doms, "domains", "domain")):
            if col in row:
                ids = []
                for part in [p.strip() for p in row[col].split(";") if p.strip()]:
                    pk = lookup.get(part.lower())
                    if pk is None:
                        errs.append(f"unknown {label} “{part}”")
                    else:
                        ids.append(pk)
                data[col] = ids
            elif inst is not None:
                # links the user cannot see are kept by CIForm.save()
                visible = set(lookup.values())
                data[col] = [pk for pk in getattr(inst, attr).values_list("pk", flat=True) if pk in visible]
        form = CIForm(data, instance=inst, user=user)
        # the form offers known sites only; an import may introduce a new site name
        if data["site"] not in dict(form.fields["site"].choices):
            form.fields["site"].choices = list(form.fields["site"].choices) + [(data["site"], data["site"])]
        if not form.is_valid():
            for field, msgs in form.errors.items():
                if field in ("ci_type", "status", "environment") and data[field] is None:
                    continue   # already reported as an unknown value above
                for m in msgs:
                    errs.append(f"{field}: {m}" if field != "__all__" else m)
        if errs:
            result["errors"].append((n, f"{name or '(no name)'}: " + "; ".join(errs)))
        else:
            forms_ok.append((form, inst is None))
    if result["errors"]:
        return result
    with transaction.atomic():
        for form, created in forms_ok:
            obj = form.save()
            result["created" if created else "updated"] += 1
            result["items"].append(obj)
    return result
