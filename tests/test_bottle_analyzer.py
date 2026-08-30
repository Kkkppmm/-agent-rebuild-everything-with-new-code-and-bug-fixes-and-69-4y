"""Tests for BottleAnalyzer."""

from pathlib import Path

from devai.bottle_analyzer import BottleAnalyzer, BottleFinding


INSECURE_BOTTLE_APP = """\
import os
import subprocess

from bottle import Bottle, redirect, request, run, static_file

SECRET = "hardcoded_secret_value"
app = Bottle()


@app.route("/admin/users")
def admin_users():
    return {"env": dict(os.environ)}


@app.route("/run")
def run_cmd():
    subprocess.run(request.forms.get("cmd"), shell=True)
    return {"ok": True}


@app.route("/files/<path:filepath>")
def serve_file(filepath):
    return static_file(filepath, root="/var/www")


@app.route("/go")
def go():
    return redirect(request.query.get("url"))


if __name__ == "__main__":
    run(app, host="0.0.0.0", port=8080, debug=True, reloader=True)
"""

HARDENED_BOTTLE_APP = """\
import os

from bottle import Bottle, run

app = Bottle()


@app.route("/health")
def health():
    return {"status": "ok"}


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
        (app_dir / "main.py").write_text(INSECURE_BOTTLE_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["bottle>=0.12.0"]\n',
            encoding="utf-8",
        )

        analyzer = BottleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_route" in kinds
        assert "debug_mode" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = BottleAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_bottle_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_BOTTLE_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["bottle>=0.12.0"]\n',
            encoding="utf-8",
        )

        analyzer = BottleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from bottle import Bottle\napp = Bottle()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["bottle"]\n',
            encoding="utf-8",
        )

        analyzer = BottleAnalyzer(str(tmp_path))
        assert "Bottle:" in analyzer.summary()
        assert "Bottle application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = BottleFinding(
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
        template = BottleAnalyzer(".").generate_hardened_template()
        assert "Bottle()" in template
        assert "health" in template
        assert "debug=False" in template
