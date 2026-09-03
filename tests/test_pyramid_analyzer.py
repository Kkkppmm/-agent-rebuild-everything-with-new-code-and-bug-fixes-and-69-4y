"""Tests for PyramidAnalyzer."""

from pathlib import Path

from devai.pyramid_analyzer import PyramidAnalyzer, PyramidFinding


INSECURE_PYRAMID_APP = """\
import os
import subprocess

from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response
from pyramid.security import Allow, ACLAllow

API_KEY = "hardcoded_secret_value"


def admin_view(request):
    return Response(body=str(dict(os.environ)))


def run_cmd(request):
    cmd = request.params.get("cmd")
    subprocess.run(cmd, shell=True)


def redirect_view(request):
    return HTTPFound(request.params.get("url"))


def render_view(request):
    return request.render(request.params.get("template"))


def main(global_config, **settings):
    config = Configurator(settings=settings)
    config.include("pyramid_debugtoolbar")
    config.add_route("admin", "/admin/users")
    config.add_view(admin_view, route_name="admin")
    config.add_route("run", "/run")
    config.add_view(run_cmd, route_name="run")
    config.add_route("redirect", "/go")
    config.add_view(redirect_view, route_name="redirect")
    config.add_route("render", "/render")
    config.add_view(render_view, route_name="render")
    config.set_root_factory(lambda: ACLAllow(Allow, "Everyone", "view"))
    return config.make_wsgi_app()
"""

INSECURE_PYRAMID_INI = """\
[app:main]
use = egg:myapp
pyramid.reload_templates = true
debug_authorization = true
session.secret = super_secret_key_12345
session.secure = false
session.httponly = false
csrf.enable = false
"""

HARDENED_PYRAMID_APP = """\
import os

from pyramid.config import Configurator
from pyramid.response import Response


def health(request):
    return Response(json_body={"status": "ok"})


def main(global_config, **settings):
    config = Configurator(settings=settings)
    config.add_route("health", "/health")
    config.add_view(health, route_name="health", renderer="json")
    return config.make_wsgi_app()
"""


class TestPyramidAnalyzer:
    def test_detects_insecure_pyramid_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_PYRAMID_APP, encoding="utf-8")
        (tmp_path / "development.ini").write_text(INSECURE_PYRAMID_INI, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["pyramid>=2.0"]\n',
            encoding="utf-8",
        )

        analyzer = PyramidAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "debug_toolbar" in kinds
        assert "shell_command" in kinds
        assert "open_redirect" in kinds
        assert "ssti" in kinds
        assert "auth_allow_all" in kinds
        assert "csrf_disabled" in kinds
        assert "insecure_session" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = PyramidAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_pyramid_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_PYRAMID_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["pyramid>=2.0"]\n',
            encoding="utf-8",
        )

        analyzer = PyramidAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from pyramid.config import Configurator\n"
            "def main(gc, **s):\n"
            "    return Configurator(settings=s).make_wsgi_app()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pyramid"]\n',
            encoding="utf-8",
        )

        analyzer = PyramidAnalyzer(str(tmp_path))
        assert "Pyramid:" in analyzer.summary()
        assert "Pyramid application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = PyramidFinding(
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
        template = PyramidAnalyzer(".").generate_hardened_template()
        assert "Configurator" in template
        assert "session.secret" in template
