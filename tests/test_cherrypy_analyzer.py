"""Tests for CherryPyAnalyzer."""

from pathlib import Path

from devai.cherrypy_analyzer import CherryPyAnalyzer, CherryPyFinding


INSECURE_CHERRYPY_APP = """\
import os
import subprocess

import cherrypy

SESSION_SECRET = "hardcoded_session_secret"
cherrypy.config.update({
    "server.socket_host": "0.0.0.0",
    "engine.autoreload.on": True,
    "environment": "development",
    "tools.sessions.on": True,
    "tools.sessions.secret": SESSION_SECRET,
    "tools.sessions.httponly": False,
    "tools.sessions.secure": False,
    "tools.xsrf.on": False,
    "tools.auth_basic.users": {"admin": "password123"},
})


class Root:
  @cherrypy.expose
  def admin_panel(self):
      return os.environ

  @cherrypy.expose
  def run(self, cmd):
      return subprocess.check_output(cmd, shell=True)

  @cherrypy.expose
  def proxy(self):
      import requests
      return requests.get("http://192.168.1.10/api", verify=False).text


if __name__ == "__main__":
    cherrypy.quickstart(Root())
"""

HARDENED_CHERRYPY_APP = """\
import os

import cherrypy


class Root:
    @cherrypy.expose
    def index(self) -> str:
        return "ok"

    @cherrypy.expose
    def health(self) -> dict[str, str]:
        return {"status": "ok"}


def create_app() -> None:
    cherrypy.config.update({
        "server.socket_host": os.environ.get("HOST", "127.0.0.1"),
        "engine.autoreload.on": False,
        "environment": "production",
        "tools.sessions.on": True,
        "tools.sessions.secret": os.environ["SESSION_SECRET"],
        "tools.sessions.httponly": True,
        "tools.sessions.secure": True,
        "tools.sessions.samesite": "Lax",
        "tools.xsrf.on": True,
    })


if __name__ == "__main__":
    create_app()
    cherrypy.quickstart(Root())
"""


class TestCherryPyAnalyzer:
    def test_detects_insecure_cherrypy_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text(INSECURE_CHERRYPY_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["cherrypy>=18.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = CherryPyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "session_secret" in kinds
        assert "xsrf_disabled" in kinds
        assert "dangerous_route" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = CherryPyAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_cherrypy_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "app.py").write_text(HARDENED_CHERRYPY_APP, encoding="utf-8")
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
        (tmp_path / "app.py").write_text(
            "import cherrypy\nclass Root:\n  pass\ncherrypy.quickstart(Root())\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["cherrypy"]\n',
            encoding="utf-8",
        )

        analyzer = CherryPyAnalyzer(str(tmp_path))
        assert "CherryPy:" in analyzer.summary()
        assert "CherryPy application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = CherryPyAnalyzer(".").generate_hardened_template()
        assert "cherrypy" in template
        assert "tools.xsrf.on" in template
        assert "tools.sessions.secure" in template

    def test_finding_format(self):
        finding = CherryPyFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()
