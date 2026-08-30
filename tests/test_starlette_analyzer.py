"""Tests for StarletteAnalyzer."""

from pathlib import Path

from devai.starlette_analyzer import StarletteAnalyzer, StarletteFinding


INSECURE_STARLETTE_APP = """\
import os
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles
from starlette.routing import Mount, Route
import httpx

SECRET_KEY = "hardcoded_secret_value"

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    ),
    Middleware(SessionMiddleware, secret_key="short"),
]

routes = [
    Route("/admin/users", endpoint=lambda r: None, methods=["GET"]),
    Route("/debug/env", endpoint=lambda r: os.environ, methods=["GET"]),
    Mount("/static", app=StaticFiles(directory=".", html=True)),
]

app = Starlette(debug=True, routes=routes, middleware=middleware)


async def proxy(request):
    async with httpx.AsyncClient(verify=False) as client:
        return await client.get("http://192.168.1.10/api")
"""

HARDENED_STARLETTE_APP = """\
import os
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route


SECRET_KEY = os.environ["STARLETTE_SECRET_KEY"]
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(",")
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "example.com").split(",")


async def health(request):
    return JSONResponse({"status": "ok"})


routes = [
    Route("/health", health, methods=["GET"]),
]

middleware = [
    Middleware(HTTPSRedirectMiddleware),
    Middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS),
    Middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    ),
    Middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True),
]

app = Starlette(debug=False, routes=routes, middleware=middleware)
"""


class TestStarletteAnalyzer:
    def test_detects_insecure_starlette_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_STARLETTE_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["starlette>=0.27.0", "httpx>=0.27.0"]\n',
            encoding="utf-8",
        )

        analyzer = StarletteAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "session_secret_short" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "static_files_root" in kinds
        assert "dangerous_route" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = StarletteAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_starlette_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_STARLETTE_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["starlette>=0.27.0"]\n',
            encoding="utf-8",
        )

        analyzer = StarletteAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from starlette.applications import Starlette\napp = Starlette()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["starlette"]\n',
            encoding="utf-8",
        )

        analyzer = StarletteAnalyzer(str(tmp_path))
        assert "Starlette:" in analyzer.summary()
        assert "Starlette application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = StarletteAnalyzer(".").generate_hardened_template()
        assert "Starlette" in template
        assert "TrustedHostMiddleware" in template
        assert "debug=False" in template

    def test_finding_format(self):
        finding = StarletteFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "main.py:1" in finding.format()

    def test_ignores_fastapi_projects(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\napp = FastAPI()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["fastapi"]\n',
            encoding="utf-8",
        )

        analyzer = StarletteAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
