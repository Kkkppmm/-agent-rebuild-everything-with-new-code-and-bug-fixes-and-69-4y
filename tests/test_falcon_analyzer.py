"""Tests for FalconAnalyzer."""

from pathlib import Path

from devai.falcon_analyzer import FalconAnalyzer, FalconFinding


INSECURE_FALCON_APP = """\
import os
import subprocess

import falcon
import falcon.asgi

SECRET_KEY = "hardcoded_secret_value"

app = falcon.asgi.App(debug=True)


class AdminResource:
    async def on_get(self, req, resp):
        resp.media = {"env": dict(os.environ)}


class RunResource:
    async def on_post(self, req, resp):
        subprocess.run(req.get_param("cmd"), shell=True)


app.add_route("/admin/users", AdminResource())
app.add_route("/run", RunResource())
"""

HARDENED_FALCON_APP = """\
import os

import falcon
import falcon.asgi


class HealthResource:
    async def on_get(self, req, resp):
        resp.media = {"status": "ok"}


def create_app() -> falcon.asgi.App:
    app = falcon.asgi.App()
    app.add_route("/health", HealthResource())
    return app


app = create_app()
"""


class TestFalconAnalyzer:
    def test_detects_insecure_falcon_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_FALCON_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["falcon>=3.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = FalconAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_route" in kinds
        assert "debug_mode" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = FalconAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_falcon_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_FALCON_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["falcon>=3.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = FalconAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "import falcon\napp = falcon.App()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["falcon"]\n',
            encoding="utf-8",
        )

        analyzer = FalconAnalyzer(str(tmp_path))
        assert "Falcon:" in analyzer.summary()
        assert "Falcon application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = FalconFinding(
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
        template = FalconAnalyzer(".").generate_hardened_template()
        assert "falcon.asgi.App" in template
        assert "HealthResource" in template
