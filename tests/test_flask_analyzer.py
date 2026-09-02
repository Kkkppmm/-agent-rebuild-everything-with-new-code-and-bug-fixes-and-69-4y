"""Tests for FlaskAnalyzer."""

from pathlib import Path

from devai.flask_analyzer import FlaskAnalyzer, FlaskFinding


INSECURE_FLASK_APP = """\
import os
import subprocess
from flask import Flask, request, send_file, render_template_string
from flask_cors import CORS

SECRET_KEY = "hardcoded_secret_value"
app = Flask(__name__)
app.config["SECRET_KEY"] = "another_hardcoded_secret"
app.config["DEBUG"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False

CORS(app, origins="*", supports_credentials=True)


@app.route("/admin/users")
def admin_users():
    return []


@app.route("/debug/env")
def debug_env():
    return os.environ


@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    return subprocess.check_output(cmd, shell=True)


@app.route("/file")
def download():
    path = request.args.get("path")
    return send_file(path)


@app.route("/preview")
def preview():
    template = request.args.get("html")
    return render_template_string(template)


@app.route("/proxy")
def proxy():
    import requests
    return requests.get("http://192.168.1.10/api", verify=False).text


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
"""

HARDENED_FLASK_APP = """\
import os

from flask import Flask
from flask_cors import CORS
from flask_talisman import Talisman


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ["SECRET_KEY"],
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        DEBUG=False,
    )

    Talisman(app, force_https=True)
    CORS(
        app,
        origins=os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
        supports_credentials=True,
    )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
"""


class TestFlaskAnalyzer:
    def test_detects_insecure_flask_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text(INSECURE_FLASK_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["flask>=3.0.0", "flask-cors>=4.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = FlaskAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "app_config_secret" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "dangerous_route" in kinds
        assert "ssti_risk" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = FlaskAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_flask_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "app.py").write_text(HARDENED_FLASK_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["flask>=3.0.0", "flask-cors>=4.0.0", "flask-talisman>=1.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = FlaskAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["flask"]\n',
            encoding="utf-8",
        )

        analyzer = FlaskAnalyzer(str(tmp_path))
        assert "Flask:" in analyzer.summary()
        assert "Flask application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = FlaskAnalyzer(".").generate_hardened_template()
        assert "Flask" in template
        assert "Talisman" in template
        assert "SESSION_COOKIE_SECURE=True" in template

    def test_finding_format(self):
        finding = FlaskFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()
