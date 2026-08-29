"""Tests for AiohttpAnalyzer."""

from pathlib import Path

from devai.aiohttp_analyzer import AiohttpAnalyzer, AiohttpFinding


INSECURE_AIOHTTP_APP = """\
import os
from aiohttp import web
from aiohttp.web import StaticRoute
from aiohttp import BasicAuth
import aiohttp

SECRET_KEY = "hardcoded_secret_value"

async def admin_users(request):
    return web.json_response([])

async def debug_env(request):
    return web.json_response(dict(os.environ))

async def proxy(request):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        return await session.get("http://192.168.1.10/api")

routes = web.RouteTableDef()

@routes.get("/admin/users")
async def admin_route(request):
    return web.json_response([])

@routes.get("/debug/env")
async def debug_route(request):
    return web.json_response(dict(os.environ))

app = web.Application(debug=True)
app.router.add_route("*", "/static/", StaticRoute("/", "/"))
app.router.add_get("/proxy", proxy)

auth = BasicAuth("admin", "password123")

# CORS wildcard with credentials
origins = "*"
allow_credentials = True
"""

HARDENED_AIOHTTP_APP = """\
import os

from aiohttp import web
from aiohttp_session import setup
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_cors import setup as cors_setup, ResourceOptions


async def health(request):
    return web.json_response({"status": "ok"})


def create_app() -> web.Application:
    app = web.Application()

    cors_setup(
        app,
        defaults={
            origin: ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods=["GET", "POST"],
            )
            for origin in os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(",")
        },
    )

    setup(
        app,
        EncryptedCookieStorage(
            os.environ["SESSION_SECRET"],
            cookie_name="session",
            max_age=3600,
            secure=True,
            httponly=True,
            samesite="Lax",
        ),
    )

    app.router.add_get("/health", health)
    return app
"""


class TestAiohttpAnalyzer:
    def test_detects_insecure_aiohttp_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_AIOHTTP_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["aiohttp>=3.9.0"]\n',
            encoding="utf-8",
        )

        analyzer = AiohttpAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "basic_auth_hardcoded" in kinds
        assert "dangerous_route" in kinds
        assert "cors_wildcard" in kinds or "tls_verify_disabled" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = AiohttpAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_aiohttp_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_AIOHTTP_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["aiohttp>=3.9.0", "aiohttp-session", "aiohttp-cors"]\n',
            encoding="utf-8",
        )

        analyzer = AiohttpAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from aiohttp import web\napp = web.Application()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["aiohttp"]\n',
            encoding="utf-8",
        )

        analyzer = AiohttpAnalyzer(str(tmp_path))
        assert "Aiohttp:" in analyzer.summary()
        assert "Aiohttp application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = AiohttpAnalyzer(".").generate_hardened_template()
        assert "web.Application" in template
        assert "EncryptedCookieStorage" in template
        assert "os.environ" in template

    def test_finding_format(self):
        finding = AiohttpFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "main.py:1" in finding.format()
