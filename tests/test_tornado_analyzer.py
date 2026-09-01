"""Tests for TornadoAnalyzer."""

from pathlib import Path

from devai.tornado_analyzer import TornadoAnalyzer, TornadoFinding


INSECURE_TORNADO_APP = """\
import os
import subprocess

import tornado.ioloop
import tornado.web

COOKIE_SECRET = "hardcoded_secret_value"


class AdminHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"env": dict(os.environ)})


class RunHandler(tornado.web.RequestHandler):
    def post(self):
        subprocess.run(self.get_argument("cmd"), shell=True)


def make_app():
    return tornado.web.Application(
        [
            (r"/admin/users", AdminHandler),
            (r"/run", RunHandler),
        ],
        cookie_secret=COOKIE_SECRET,
        xsrf_cookies=False,
        debug=True,
        autoreload=True,
    )


app = make_app()
"""

HARDENED_TORNADO_APP = """\
import os

import tornado.ioloop
import tornado.web


class HealthHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"status": "ok"})


def make_app():
    return tornado.web.Application(
        [
            (r"/health", HealthHandler),
        ],
        cookie_secret=os.environ.get("COOKIE_SECRET"),
        xsrf_cookies=True,
        debug=False,
        autoreload=False,
    )


app = make_app()
"""


class TestTornadoAnalyzer:
    def test_detects_insecure_tornado_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_TORNADO_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["tornado>=6.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = TornadoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_route" in kinds
        assert "debug_mode" in kinds
        assert "xsrf_disabled" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = TornadoAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_tornado_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_TORNADO_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["tornado>=6.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = TornadoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "import tornado.web\napp = tornado.web.Application([])\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["tornado"]\n',
            encoding="utf-8",
        )

        analyzer = TornadoAnalyzer(str(tmp_path))
        assert "Tornado:" in analyzer.summary()
        assert "Tornado application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = TornadoFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
            line="SECRET = 'x'",
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()

    def test_generate_hardened_template(self):
        template = TornadoAnalyzer(".").generate_hardened_template()
        assert "tornado.web.Application" in template
        assert "HealthHandler" in template
        assert "xsrf_cookies=True" in template
