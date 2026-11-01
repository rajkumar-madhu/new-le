import logging
import signal
import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from core import jobs
from probes import runner

log = logging.getLogger("linkedeye.probes")


class Command(BaseCommand):
    help = "Run URL and domain checks that are due. Loops until stopped unless --once is given."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Run due checks once and exit.")
        parser.add_argument("--tick", type=int, default=15, help="Seconds between scheduler passes (default 15).")

    def handle(self, *args, once=False, tick=15, **opts):
        stop = {"flag": False}
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.update(flag=True))
        last_prune = 0.0
        while True:
            close_old_connections()
            started = time.monotonic()
            try:
                urls, domains = runner.run_due()
                if urls or domains:
                    self.stdout.write(f"checked {urls} URL(s), {domains} domain(s) in {time.monotonic() - started:.1f}s")
                for name, summary in jobs.run_due().items():
                    if summary:
                        self.stdout.write(f"{name}: {summary}")
                if time.monotonic() - last_prune > 3600:
                    removed = runner.prune()
                    last_prune = time.monotonic()
                    if removed:
                        self.stdout.write(f"pruned {removed} old result(s)")
            except Exception:  # keep the scheduler alive; the error is logged with traceback
                log.exception("probe pass failed")
            if once or stop["flag"]:
                break
            while time.monotonic() - started < tick and not stop["flag"]:
                time.sleep(0.5)
