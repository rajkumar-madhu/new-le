"""Regression tests for the deployment bundle (no Docker daemon, cluster or Django database needed).

    pip install pyyaml && python -m unittest discover -s deploy/tests -v

Covers gunicorn.conf.py, deploy/docker/healthcheck.py, deploy/validate.py (run against mutated copies of the
bundle) and a few file-level rules of the Dockerfile context, compose file and Kubernetes manifests.
"""
import http.server
import importlib.util
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


healthcheck = load_module("le_healthcheck", ROOT / "deploy" / "docker" / "healthcheck.py")


def gunicorn_conf(env):
    """Execute gunicorn.conf.py with only `env` as GUNICORN_*/LINKEDEYE_* variables; returns its namespace."""
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("GUNICORN_", "LINKEDEYE_"))}
    clean.update(env)
    stub = {}
    try:
        importlib.import_module("gunicorn.glogging")
    except ImportError:  # the dev venv may not have gunicorn; the config only needs Logger as a base class
        glogging = types.ModuleType("gunicorn.glogging")
        glogging.Logger = type("Logger", (), {"access": lambda self, *a: None})
        stub = {"gunicorn": types.ModuleType("gunicorn"), "gunicorn.glogging": glogging}
    with mock.patch.dict(os.environ, clean, clear=True), mock.patch.dict(sys.modules, stub):
        return runpy.run_path(str(ROOT / "gunicorn.conf.py"))


class GunicornConfTests(unittest.TestCase):
    def test_defaults(self):
        conf = gunicorn_conf({})
        self.assertEqual(conf["bind"], ["0.0.0.0:8000"])
        self.assertEqual(conf["worker_class"], "gthread")
        self.assertTrue(1 <= conf["workers"] <= 8)
        self.assertEqual(conf["wsgi_app"], "container_wsgi:application")

    def test_bind_accepts_a_comma_separated_list(self):
        # regression: the whole string used to become one bogus address
        conf = gunicorn_conf({"GUNICORN_BIND": "0.0.0.0:8000, [::]:8000,"})
        self.assertEqual(conf["bind"], ["0.0.0.0:8000", "[::]:8000"])

    def test_counts_are_clamped_and_garbage_falls_back(self):
        conf = gunicorn_conf({"GUNICORN_WORKERS": "-3", "GUNICORN_THREADS": "0", "GUNICORN_TIMEOUT": "0",
                              "GUNICORN_MAX_REQUESTS": "-5"})
        self.assertEqual((conf["workers"], conf["threads"], conf["timeout"], conf["max_requests"]), (1, 1, 1, 0))
        self.assertEqual(conf["worker_class"], "sync")
        conf = gunicorn_conf({"GUNICORN_THREADS": "many"})
        self.assertEqual(conf["threads"], 4)

    def test_on_starting_refuses_template_placeholders(self):
        server = mock.Mock()
        conf = gunicorn_conf({"LINKEDEYE_SECRET_KEY": "<REPLACE: 50+ random characters>"})
        with mock.patch.dict(os.environ, {"LINKEDEYE_SECRET_KEY": "<REPLACE: 50+ random characters>"}):
            with self.assertRaisesRegex(RuntimeError, "LINKEDEYE_SECRET_KEY"):
                conf["on_starting"](server)
        with mock.patch.dict(os.environ, {"LINKEDEYE_SECRET_KEY": "a-real-key"}):
            conf["on_starting"](server)
        server.log.info.assert_called()

    def test_access_log_skips_successful_healthz_only(self):
        conf = gunicorn_conf({})
        logger = conf["LinkedEyeLogger"].__new__(conf["LinkedEyeLogger"])
        with mock.patch.object(conf["LinkedEyeLogger"].__mro__[1], "access") as parent:
            logger.access(mock.Mock(status="200 OK"), None, {"PATH_INFO": "/healthz"}, 0)
            parent.assert_not_called()
            logger.access(mock.Mock(status="500 Internal Server Error"), None, {"PATH_INFO": "/healthz"}, 0)
            logger.access(mock.Mock(status="200 OK"), None, {"PATH_INFO": "/"}, 0)
            self.assertEqual(parent.call_count, 2)


class HealthcheckTests(unittest.TestCase):
    def test_target_from_bind(self):
        t = healthcheck._target
        self.assertEqual(t(""), ("127.0.0.1", 8000))
        self.assertEqual(t("0.0.0.0:9000"), ("127.0.0.1", 9000))
        self.assertEqual(t("[::]:8000"), ("::1", 8000))
        self.assertEqual(t("10.0.0.5:8080,0.0.0.0:8000"), ("10.0.0.5", 8080))
        # regression: a unix socket first used to make the check probe port 8000 of nothing
        self.assertEqual(t("unix:/tmp/g.sock,0.0.0.0:8100"), ("127.0.0.1", 8100))
        self.assertEqual(t("localhost"), ("localhost", 8000))
        self.assertEqual(t("bogus:port"), ("127.0.0.1", 8000))

    def test_host_header(self):
        with mock.patch.dict(os.environ, {"LINKEDEYE_ALLOWED_HOSTS": " .example.com ,web"}):
            self.assertEqual(healthcheck._host_header(), "example.com")
        with mock.patch.dict(os.environ, {"LINKEDEYE_ALLOWED_HOSTS": "*"}):
            self.assertEqual(healthcheck._host_header(), "localhost")

    def test_placeholders(self):
        env = {"LINKEDEYE_SECRET_KEY": "<REPLACE: x>", "LINKEDEYE_DB_PASSWORD": "ok", "OTHER": "<REPLACE>",
               "LINKEDEYE_NAGIOS_PASSWORD": "pre <REPLACE: y>"}
        self.assertEqual(healthcheck.placeholder_variables(env), ["LINKEDEYE_NAGIOS_PASSWORD", "LINKEDEYE_SECRET_KEY"])
        self.assertFalse(healthcheck.check_preflight(env)[0])
        self.assertTrue(healthcheck.check_preflight({"LINKEDEYE_SECRET_KEY": "k"})[0])

    def test_main_modes(self):
        with mock.patch("builtins.print"):
            self.assertEqual(healthcheck.main(["hc", "bogus"]), 2)
            with mock.patch.dict(os.environ, {"LINKEDEYE_STACKSTORM_API_KEY": "<REPLACE: key>"}):
                self.assertEqual(healthcheck.main(["hc", "preflight"]), 1)

    def _serve(self, status):
        seen = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen["host"], seen["path"] = self.headers.get("Host"), self.path
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1], seen

    def test_check_web(self):
        port, seen = self._serve(200)
        env = {"GUNICORN_BIND": f"unix:/tmp/x.sock,0.0.0.0:{port}", "LINKEDEYE_ALLOWED_HOSTS": "le.example.com"}
        with mock.patch.dict(os.environ, env):
            ok, msg = healthcheck.check_web()
        self.assertTrue(ok, msg)
        self.assertEqual(seen, {"host": "le.example.com", "path": "/healthz"})

        port, _ = self._serve(400)
        with mock.patch.dict(os.environ, {"GUNICORN_BIND": f"127.0.0.1:{port}"}):
            ok, msg = healthcheck.check_web()
        self.assertFalse(ok)
        self.assertIn("ALLOWED_HOSTS", msg)


# ------------------------------------------------------------------ deploy/validate.py on mutated copies
BUNDLE = ["deploy", "docker-compose.yml", "Dockerfile", ".github", "docs/DEPLOYMENT.md", "linkedeye/settings.py",
          "administration/services.py", "telemetry/nagios.py"]


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="le-validate-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for rel in BUNDLE:
            src, dst = ROOT / rel, self.tmp / rel
            if not src.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "tests"))
            else:
                shutil.copy2(src, dst)

    def run_validate(self):
        proc = subprocess.run([sys.executable, str(self.tmp / "deploy" / "validate.py")],
                              capture_output=True, text=True, timeout=60)
        self.assertNotIn("Traceback", proc.stderr, proc.stderr)
        return proc.returncode, proc.stdout

    def edit(self, rel, old, new):
        path = self.tmp / rel
        text = path.read_text()
        self.assertIn(old, text, f"fixture drift in {rel}")
        path.write_text(text.replace(old, new))

    def assertFails(self, needle):
        rc, out = self.run_validate()
        self.assertEqual(rc, 1, out)
        self.assertIn(needle, out)

    def test_bundle_as_shipped_is_valid(self):
        rc, out = self.run_validate()
        self.assertEqual(rc, 0, out)

    def test_second_probe_scheduler_is_caught(self):
        self.edit("deploy/kubernetes/probes-deployment.yaml", "replicas: 1", "replicas: 2")
        self.assertFails("exactly 1 replica")

    def test_short_depends_on_syntax_reports_instead_of_crashing(self):
        # regression: a list-style depends_on raised AttributeError with a traceback
        self.edit("docker-compose.yml", """    stop_grace_period: 40s
    depends_on:
      db:
        condition: service_healthy
      migrate:
        condition: service_completed_successfully""", """    stop_grace_period: 40s
    depends_on: [db, migrate]""")
        self.assertFails("web must wait for a healthy db")

    def test_image_pinned_by_digest_is_accepted(self):
        # regression: "repo@sha256:..." was cut at the last ":" and reported as a different image
        digest = "@sha256:" + "a" * 64
        for name in ("web-deployment.yaml", "probes-deployment.yaml", "migrate-job.yaml"):
            path = self.tmp / "deploy" / "kubernetes" / name
            path.write_text(path.read_text().replace("registry.example.com/linkedeye:9.0",
                                                     "registry.example.com:5000/linkedeye" + digest))
        self.edit("deploy/kubernetes/kustomization.yaml", "  - name: registry.example.com/linkedeye\n",
                  "  - name: registry.example.com:5000/linkedeye\n")
        rc, out = self.run_validate()
        self.assertEqual(rc, 0, out)

    def test_migrate_job_without_preflight_is_caught(self):
        self.edit("deploy/kubernetes/migrate-job.yaml",
                  "python /app/deploy/docker/healthcheck.py preflight && exec ", "exec ")
        self.assertFails("Job/linkedeye-migrate: must run healthcheck.py preflight")

    def test_init_container_without_preflight_is_caught(self):
        self.edit("deploy/kubernetes/web-deployment.yaml",
                  "python /app/deploy/docker/healthcheck.py preflight || exit 1", "true")
        self.assertFails("Deployment/linkedeye-web: an init container must run healthcheck.py preflight")

    def test_alertmanager_healthcheck_must_cover_the_token_file(self):
        self.edit("docker-compose.yml", "test -s /run/secrets/alertmanager_webhook_token && ", "")
        self.assertFails("alertmanager healthcheck")

    def test_documented_variable_that_does_not_exist_is_caught(self):
        self.edit("docs/DEPLOYMENT.md", "## Backups", "Set `LINKEDEYE_DB_CONN_MAX_AGEE` too.\n\n## Backups")
        self.assertFails("LINKEDEYE_DB_CONN_MAX_AGEE is not read by the application")

    def test_real_value_in_secret_template_is_caught(self):
        self.edit("deploy/kubernetes/secret.template.yaml", '"<REPLACE: database password for LINKEDEYE_DB_USER>"',
                  '"hunter2"')
        self.assertFails("LINKEDEYE_DB_PASSWORD must be a <REPLACE ...> placeholder")

    def test_undocumented_setting_is_caught(self):
        self.edit("linkedeye/settings.py", 'LINKEDEYE_TENANT = env("TENANT", "default")',
                  'LINKEDEYE_TENANT = env("TENANT", "default")\nX = env("NEW_KNOB", "1")')
        self.assertFails("LINKEDEYE_NEW_KNOB is not documented")


# ------------------------------------------------------------------ file-level rules
class FileRuleTests(unittest.TestCase):
    def test_dockerignore_excludes_local_state_at_any_depth(self):
        lines = {ln.strip() for ln in (ROOT / ".dockerignore").read_text().splitlines()}
        for pattern in ("**/*.sqlite3", "**/.env", "**/*.log", ".git", ".venv"):
            self.assertIn(pattern, lines)

    def test_compose_alertmanager_unhealthy_without_token(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        test = " ".join(compose["services"]["alertmanager"]["healthcheck"]["test"])
        self.assertIn("test -s /run/secrets/alertmanager_webhook_token", test)

    def test_backup_job_removes_partial_dumps(self):
        docs = list(yaml.safe_load_all((ROOT / "deploy/kubernetes/optional/backup-cronjob.yaml").read_text()))
        cron = next(d for d in docs if d["kind"] == "CronJob")
        script = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["command"][-1]
        self.assertIn("set -eu", script)
        self.assertIn("trap 'rm -f \"$file.partial\"' EXIT", script)
        self.assertIn("-name 'linkedeye-*.dump.partial'", script)

    def test_every_kubernetes_app_container_runs_the_preflight_first(self):
        for name in ("web-deployment.yaml", "probes-deployment.yaml"):
            dep = next(d for d in yaml.safe_load_all((ROOT / "deploy/kubernetes" / name).read_text())
                       if d["kind"] == "Deployment")
            script = dep["spec"]["template"]["spec"]["initContainers"][0]["command"][-1]
            self.assertLess(script.index("healthcheck.py preflight"), script.index("migrate --check"), name)


if __name__ == "__main__":
    unittest.main()
