"""Tests for LitestarAnalyzer."""

from pathlib import Path

from devai.litestar_analyzer import LitestarAnalyzer, LitestarFinding


INSECURE_LITESTAR_APP = """\
import os
from litestar import Litestar, get, post
from litestar.config.cors import CORSConfig
from litestar.config.csrf import CSRFConfig
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.openapi import OpenAPIConfig
import httpx

SECRET_KEY = "hardcoded_secret_value"

@get("/admin/users")
async def admin_users() -> dict:
    return {}

@get("/debug/env")
async def debug_env() -> dict:
    return dict(os.environ)

@post("/proxy")
async def proxy() -> None:
    async with httpx.AsyncClient(verify=False) as client:
        await client.get("http://192.168.1.10/api")

cors_config = CORSConfig(
    allow_origins=["*"],
    allow_credentials=True,
)

app = Litestar(
    route_handlers=[admin_users, debug_env, proxy],
    cors_config=cors_config,
    csrf_config=None,
    middleware=[
        ServerSideSessionConfig(secret="session_secret_hardcoded").middleware,
    ],
    openapi_config=OpenAPIConfig(title="API", version="1.0.0", enabled=True, path="/docs"),
    debug=True,
    allowed_hosts=["*"],
)
"""

HARDENED_LITESTAR_APP = """\
import os

from litestar import Litestar, get
from litestar.config.cors import CORSConfig
from litestar.config.csrf import CSRFConfig
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.openapi import OpenAPIConfig


@get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def create_app() -> Litestar:
    allowed_origins = os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(",")

    return Litestar(
        route_handlers=[health],
        cors_config=CORSConfig(
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        ),
        csrf_config=CSRFConfig(secret=os.environ["CSRF_SECRET"]),
        middleware=[
            ServerSideSessionConfig(
                secret=os.environ["SESSION_SECRET"],
                max_age=3600,
                secure=True,
                httponly=True,
                samesite="lax",
            ).middleware,
        ],
        openapi_config=OpenAPIConfig(
            title="API",
            version="1.0.0",
            enabled=os.environ.get("ENABLE_OPENAPI", "false").lower() == "true",
        ),
        debug=False,
        allowed_hosts=os.environ.get("ALLOWED_HOSTS", "example.com").split(","),
    )
"""


class TestLitestarAnalyzer:
    def test_detects_insecure_litestar_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_LITESTAR_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["litestar>=2.0"]\n',
            encoding="utf-8",
        )

        analyzer = LitestarAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "dangerous_route" in kinds
        assert "cors_wildcard" in kinds
        assert "csrf_disabled" in kinds
        assert "debug_mode" in kinds
        assert "ssrf_internal" in kinds
        assert analyzer.stats.findings > 0
        assert analyzer.health_score() < 100.0

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_LITESTAR_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["litestar>=2.0"]\n',
            encoding="utf-8",
        )

        analyzer = LitestarAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        high_findings = [f for f in findings if f.severity == "high"]
        assert len(high_findings) == 0
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = LitestarFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="main.py",
            lineno=10,
            line="SECRET = 'bad'",
        )
        assert "[high] main.py:10" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = LitestarAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "Litestar" in template
        assert "CSRFConfig" in template
        assert "os.environ" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_LITESTAR_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["litestar"]\n',
            encoding="utf-8",
        )

        analyzer = LitestarAnalyzer(str(tmp_path))
        assert "Litestar:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Litestar application analysis:" in context
        assert "health score:" in context

    def test_no_litestar_project(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
        analyzer = LitestarAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.summary() == "Litestar: no application files found"
