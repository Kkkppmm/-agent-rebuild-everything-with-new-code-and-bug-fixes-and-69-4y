"""Tests for QuartAnalyzer."""

from pathlib import Path

from devai.quart_analyzer import QuartAnalyzer, QuartFinding


INSECURE_QUART_APP = """\
import os
from quart import Quart, request, render_template_string
from quart_cors import cors

SECRET_KEY = "hardcoded_secret_value"
app = Quart(__name__)
app.config["SECRET_KEY"] = "another_hardcoded_secret"
app.config["DEBUG"] = True

app = cors(app, allow_origin="*", allow_credentials=True)


@app.route("/admin/users")
async def admin_users():
    return []


@app.route("/debug/env")
async def debug_env():
    return os.environ


@app.route("/preview")
async def preview():
    template = request.args.get("html")
    return await render_template_string(template)


@app.route("/proxy")
async def proxy():
    import httpx
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get("http://192.168.1.10/api")
        return resp.text


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
"""

HARDENED_QUART_APP = """\
import os

from quart import Quart
from quart_cors import cors


def create_app() -> Quart:
    app = Quart(__name__)
    app.config.update(
        SECRET_KEY=os.environ["SECRET_KEY"],
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        DEBUG=False,
    )

    app = cors(
        app,
        allow_origin=os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
        allow_credentials=True,
    )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


app = create_app()
"""


class TestQuartAnalyzer:
    def test_detects_insecure_quart_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_QUART_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["quart>=0.19.0", "quart-cors>=0.7.0", "httpx>=0.27.0"]\n',
            encoding="utf-8",
        )

        analyzer = QuartAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "app_config_secret" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "ssti" in kinds
        assert "dangerous_route" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = QuartAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_quart_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_QUART_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["quart>=0.19.0", "quart-cors>=0.7.0"]\n',
            encoding="utf-8",
        )

        analyzer = QuartAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from quart import Quart\napp = Quart(__name__)\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["quart"]\n',
            encoding="utf-8",
        )

        analyzer = QuartAnalyzer(str(tmp_path))
        assert "Quart:" in analyzer.summary()
        assert "Quart application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = QuartAnalyzer(".").generate_hardened_template()
        assert "Quart" in template
        assert "cors" in template
        assert "os.environ" in template

    def test_finding_format(self):
        finding = QuartFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "main.py:1" in finding.format()
