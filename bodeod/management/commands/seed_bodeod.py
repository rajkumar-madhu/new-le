"""Create clearly-marked example BOD / EOD configuration. Idempotent; never runs automatically.

* Modes BOD, EOD and ADP with Indian market windows (IST). Existing modes are left untouched.
* Checklists that reference the URL checks and domains created by `manage.py seed_examples` (and the TCP checks
  from `seed_tcpcheck`) by name; until those exist the items report UNKNOWN. Instructions start with "Example".
* 2026 NSE trading holidays with source "example" – verify them against the official NSE circular.

No run results are created: runs happen only when someone presses Run now or the scheduler starts them.
"""
from datetime import date, time

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from bodeod.models import ChecklistItem, Holiday, Mode

MODES = [
    {"code": "BOD", "name": "Beginning of Day", "window_start": time(7, 0), "window_end": time(9, 0), "auto_run_time": time(7, 15),
     "description": "Example: pre-open readiness of exchange connectivity, portals and trading systems."},
    {"code": "EOD", "name": "End of Day", "window_start": time(15, 30), "window_end": time(16, 0), "auto_run_time": time(15, 40),
     "description": "Example: post-close checks before end-of-day processing starts."},
    {"code": "ADP", "name": "After-Day Processing", "window_start": time(16, 0), "window_end": time(20, 0), "auto_run_time": time(16, 30),
     "description": "Example: overnight batch and file-transfer readiness."},
]

# (mode, order, name, kind, ref_name, critical, instructions)
ITEMS = [
    ("BOD", 10, "NSE portal reachable", "url_check", "NSE Web Portal", True, "Example: NSE public website must be online before 09:00."),
    ("BOD", 20, "BSE portal reachable", "url_check", "BSE Portal", True, "Example: BSE public website must be online before 09:00."),
    ("BOD", 30, "MCX portal reachable", "url_check", "MCX Portal", False, "Example: MCX public website (non-critical for equity BOD)."),
    ("BOD", 40, "nseindia.com DNS & SSL", "domain", "nseindia.com", True, "Example: DNS resolves and the certificate is valid."),
    ("BOD", 50, "bseindia.com DNS & SSL", "domain", "bseindia.com", True, "Example: DNS resolves and the certificate is valid."),
    ("BOD", 60, "Public DNS resolver (TCP 53)", "tcp_check", "Example – Cloudflare DNS (TCP 53)", False,
     "Example: resolver reachability over TCP (needs `manage.py seed_tcpcheck`)."),
    ("BOD", 70, "Market data feed connected", "manual", "", True,
     "Example: confirm the market-data feed handler shows a live connection to the exchange multicast."),
    ("BOD", 80, "Risk management system started", "manual", "", True,
     "Example: RMS is up, limits are loaded and the previous day's positions are carried forward."),
    ("EOD", 10, "NSE portal reachable", "url_check", "NSE Web Portal", True, "Example: portal available for bhavcopy downloads."),
    ("EOD", 20, "BSE portal reachable", "url_check", "BSE Portal", False, "Example: portal available for EOD reports."),
    ("EOD", 30, "mcxindia.com DNS & SSL", "domain", "mcxindia.com", False, "Example: commodity segment domain healthy."),
    ("EOD", 40, "Trade file received", "manual", "", True, "Example: the exchange trade file for today is received and its record count matches the OMS."),
    ("EOD", 50, "Bhavcopy downloaded", "manual", "", False, "Example: today's bhavcopy is downloaded and archived."),
    ("ADP", 10, "Finspot website online", "url_check", "Finspot Website", False, "Example: client portal available for contract notes."),
    ("ADP", 20, "finspot.in DNS & SSL", "domain", "finspot.in", False, "Example: domain healthy before contract notes are mailed."),
    ("ADP", 30, "Contract notes generated", "manual", "", True, "Example: contract notes generated and the dispatch job has started."),
    ("ADP", 40, "Backups completed", "manual", "", True, "Example: overnight database backups finished without errors."),
]

# NSE trading holidays 2026 (example data – verify against the official NSE circular before relying on it)
HOLIDAYS_2026 = [
    (date(2026, 1, 26), "Republic Day"),
    (date(2026, 3, 3), "Holi"),
    (date(2026, 3, 26), "Shri Ram Navami"),
    (date(2026, 3, 31), "Shri Mahavir Jayanti"),
    (date(2026, 4, 3), "Good Friday"),
    (date(2026, 4, 14), "Dr. Baba Saheb Ambedkar Jayanti"),
    (date(2026, 5, 1), "Maharashtra Day"),
    (date(2026, 5, 28), "Bakri Id"),
    (date(2026, 6, 26), "Muharram"),
    (date(2026, 9, 14), "Ganesh Chaturthi"),
    (date(2026, 10, 2), "Mahatma Gandhi Jayanti"),
    (date(2026, 10, 20), "Dussehra"),
    (date(2026, 11, 10), "Diwali Balipratipada"),
    (date(2026, 11, 24), "Prakash Gurpurb Sri Guru Nanak Dev"),
    (date(2026, 12, 25), "Christmas"),
]


class Command(BaseCommand):
    help = "Create example BOD/EOD/ADP modes, checklists and 2026 NSE holidays (marked 'Example'; idempotent)."

    def add_arguments(self, parser):
        parser.add_argument("--remove", action="store_true",
                            help="Delete the example holidays and example checklist items (modes and runs are kept).")

    @transaction.atomic
    def handle(self, *args, remove=False, **opts):
        tenant = settings.LINKEDEYE_TENANT
        if remove:
            h, _ = Holiday.objects.filter(tenant_key=tenant, source="example").delete()
            i, _ = ChecklistItem.objects.filter(mode__tenant_key=tenant, instructions__startswith="Example").delete()
            self.stdout.write(self.style.SUCCESS(f"Removed {h} example holiday(s) and {i} example checklist item(s)."))
            return
        modes, n_modes, n_items, n_hol = {}, 0, 0, 0
        for spec in MODES:
            spec = dict(spec)
            code = spec.pop("code")
            mode, created = Mode.objects.get_or_create(tenant_key=tenant, code=code, defaults=spec)
            modes[code] = mode
            n_modes += created
        for code, order, name, kind, ref, critical, instr in ITEMS:
            _, created = ChecklistItem.objects.get_or_create(mode=modes[code], name=name, defaults={
                "order": order, "kind": kind, "ref_name": ref, "critical": critical, "instructions": instr})
            n_items += created
        for d, desc in HOLIDAYS_2026:
            _, created = Holiday.objects.get_or_create(tenant_key=tenant, exchange="NSE", date=d, defaults={
                "description": desc, "source": "example"})
            n_hol += created
        self.stdout.write(self.style.SUCCESS(
            f"Created {n_modes} mode(s), {n_items} checklist item(s) and {n_hol} example holiday(s). "
            "Items reference the URL checks/domains from `seed_examples` and TCP checks from `seed_tcpcheck`."))
