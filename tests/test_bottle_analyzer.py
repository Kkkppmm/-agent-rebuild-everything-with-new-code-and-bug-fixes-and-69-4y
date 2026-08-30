"""Tests for BottleAnalyzer."""

from pathlib import Path

from devai.bottle_analyzer import BottleAnalyzer, BottleFinding


INSECURE_BOTTLE_APP = """\
import os
import subprocess
from bottle import Bottle, run, request, static_file, template

SECRET_KEY = "hardcoded_secret_value"
app = Bottle()

@app.route("/admin/users")
def admin_users():
    return []


@app.route("/debug/env")
def debug_env():
    return os.environ


@app.route("/run")
def run_cmd():
    cmd = request.query.get("cmd")
    return subprocess.check_output(cmd, shell=True)


@app.route("/file/<filename:path>")
def download(filename):
    return static_file(filename, root=request.query.get("root"))


@app.route("/preview")
def preview():
    html = request.query.get("html")
    return template(html)


@app.route("/proxy")
def proxy():
    import requests
    return requests.get("http://192.168.1.10/api", verify=False).text


if __name__ == "__main__":
    run(app, host="0.0.0.0", debug=True, reloader=True)
"""

HARDENED_BOTTLE_APP = """\
import os

from bottle import Bottle, run


def create_app() -> Bottle:
    app = Bottle()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()

if __name__ == "__main__":
    run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
        debug=False,
        reloader=False,
    )
"""


class TestBottleAnalyzer:
    def test_detects_insecure_bottle_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text(INSECURE_BOTTLE_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["bottle>=0.13.0"]\n',
            encoding="utf-8",
        )

        analyzer = BottleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_route" in kinds
        assert "ssti_risk" in kinds
        assert "shell_command" in kinds
        assert "path_traversal_static_file" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = BottleAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_bottle_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "app.py").write_text(HARDENED_BOTTLE_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["bottle>=0.13.0"]\n',
            encoding="utf-8",
        )

        analyzer = BottleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from bottle import Bottle\napp = Bottle()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["bottle"]\n',
            encoding="utf-8",
        )

        analyzer = BottleAnalyzer(str(tmp_path))
        assert "Bottle:" in analyzer.summary()
        assert "Bottle application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = BottleAnalyzer(".").generate_hardened_template()
        assert "Bottle" in template
        assert "debug=False" in template
        assert "reloader=False" in template

    def test_finding_format(self):
        finding = BottleFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "app.py").write_text(
            "from bottle import Bottle\napp = Bottle()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["bottle"]\n',
            encoding="utf-8",
        )

        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "bottle" in names
