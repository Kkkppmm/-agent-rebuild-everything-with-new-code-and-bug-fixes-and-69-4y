"""Tests for SanicAnalyzer."""

from pathlib import Path

from devai.sanic_analyzer import SanicAnalyzer, SanicFinding


INSECURE_SANIC_APP = """\
import os
from sanic import Sanic, response
from sanic_ext import Extend, cors
from jinja2 import Environment

SECRET = "hardcoded_secret_value"
app = Sanic(__name__)
app.config.SECRET = "another_hardcoded_secret"
app.config.DEBUG = True

Extend(app)
cors(app, resources={r"/*": {"origins": "*", "supports_credentials": True}})


@app.route("/admin/users")
async def admin_users(request):
    return response.json([])


@app.route("/debug/env")
async def debug_env(request):
    return response.json(dict(os.environ))


@app.route("/preview")
async def preview(request):
    template = request.args.get("html")
    return response.html(Environment().from_string(template).render())


@app.route("/proxy")
async def proxy(request):
    import httpx
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get("http://192.168.1.10/api")
        return response.text(resp.text)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
"""

HARDENED_SANIC_APP = """\
import os

from sanic import Sanic, response
from sanic_ext import Extend, cors


def create_app():
    app = Sanic(__name__)
    app.config.SECRET = os.environ["SECRET_KEY"]
    app.config.DEBUG = False

    Extend(app)
    cors(
        app,
        resources={
            r"/*": {
                "origins": os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
                "supports_credentials": True,
            }
        },
    )

    @app.get("/health")
    async def health(request):
        return response.json({"status": "ok"})

    return app


app = create_app()
"""


class TestSanicAnalyzer:
    def test_detects_insecure_sanic_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_SANIC_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["sanic>=23.0.0", "sanic-ext>=23.0.0", "httpx>=0.27.0"]\n',
            encoding="utf-8",
        )

        analyzer = SanicAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "app_config_secret" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "ssti" in kinds
        assert "dangerous_route" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = SanicAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_sanic_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_SANIC_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["sanic>=23.0.0", "sanic-ext>=23.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = SanicAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from sanic import Sanic\napp = Sanic(__name__)\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["sanic"]\n',
            encoding="utf-8",
        )

        analyzer = SanicAnalyzer(str(tmp_path))
        assert "Sanic:" in analyzer.summary()
        assert "Sanic application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = SanicAnalyzer(".").generate_hardened_template()
        assert "Sanic" in template
        assert "cors" in template
        assert "os.environ" in template

    def test_finding_format(self):
        finding = SanicFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "main.py:1" in finding.format()
