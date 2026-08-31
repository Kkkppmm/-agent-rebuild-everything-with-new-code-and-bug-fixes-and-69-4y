"""Tests for CherryPyAnalyzer."""

from pathlib import Path

from devai.cherrypy_analyzer import CherryPyAnalyzer, CherryPyFinding


INSECURE_CHERRYPY_APP = """\
import os
import subprocess

import cherrypy


class Admin:
    @cherrypy.expose
    def admin_users(self):
        return {"env": dict(os.environ)}

    @cherrypy.expose
    def run(self, cmd):
        subprocess.run(cmd, shell=True)


SESSION_SECRET = "hardcoded_secret_value"

cherrypy.config.update(
    {
        "server.socket_host": "0.0.0.0",
        "server.environment": "development",
        "engine.autoreload.on": True,
        "tools.sessions.on": True,
        "tools.sessions.secret": SESSION_SECRET,
    }
)

cherrypy.response.headers["Access-Control-Allow-Origin"] = "*"
cherrypy.response.headers["Access-Control-Allow-Credentials"] = True

cherrypy.quickstart(Admin(), "/")
"""

HARDENED_CHERRYPY_APP = """\
import os

import cherrypy


class Health:
    @cherrypy.expose
    def index(self):
        return {"status": "ok"}


def main():
    cherrypy.config.update(
        {
            "server.socket_host": os.environ.get("HOST", "127.0.0.1"),
            "server.environment": "production",
            "engine.autoreload.on": False,
            "tools.sessions.on": True,
            "tools.sessions.secret": os.environ.get("SESSION_SECRET"),
        }
    )
    cherrypy.quickstart(Health(), "/health")


if __name__ == "__main__":
    main()
"""


class TestCherryPyAnalyzer:
    def test_detects_insecure_cherrypy_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_CHERRYPY_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["cherrypy>=18.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = CherryPyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "debug_mode" in kinds
        assert "bind_all_interfaces" in kinds
        assert "shell_command" in kinds
        assert "cors_wildcard" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = CherryPyAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_cherrypy_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_CHERRYPY_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["cherrypy>=18.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = CherryPyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "import cherrypy\ncherrypy.quickstart(object(), '/')\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["cherrypy"]\n',
            encoding="utf-8",
        )

        analyzer = CherryPyAnalyzer(str(tmp_path))
        assert "CherryPy:" in analyzer.summary()
        assert "CherryPy application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = CherryPyFinding(
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
        template = CherryPyAnalyzer(".").generate_hardened_template()
        assert "cherrypy.config.update" in template
        assert "server.environment" in template
        assert "engine.autoreload.on" in template
