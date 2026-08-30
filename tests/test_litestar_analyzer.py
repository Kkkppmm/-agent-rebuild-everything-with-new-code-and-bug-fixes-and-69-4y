"""Tests for LitestarAnalyzer."""

from pathlib import Path

from devai.litestar_analyzer import LitestarAnalyzer, LitestarFinding


INSECURE_LITESTAR_APP = """\
import os
from litestar import Litestar, get, post
from litestar.config.cors import CORSConfig
from litestar.config.csrf import CSRFConfig
from litestar.middleware.session import SessionConfig
import httpx

SECRET_KEY = "hardcoded_secret_value"

@get("/admin/users")
async def admin_users() -> dict:
    return {}

@get("/debug/env")
async def debug_env() -> dict:
    return dict(os.environ)

@post("/proxy")
async def proxy() -> str:
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get("http://192.168.1.10/api")
        return resp.text

app = Litestar(
    route_handlers=[admin_users, debug_env, proxy],
    debug=True,
    cors_config=CORSConfig(
        allow_origins=["*"],
        allow_credentials=True,
    ),
    csrf_config=CSRFConfig(enabled=False),
    session_config=SessionConfig(secret="session_secret_123"),
)
"""

HARDENED_LITESTAR_APP = """\
import os

from litestar import Litestar, get
from litestar.config.cors import CORSConfig
from litestar.config.csrf import CSRFConfig
from litestar.middleware.session import SessionConfig


@get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app = Litestar(
    route_handlers=[health],
    debug=False,
    cors_config=CORSConfig(
        allow_origins=os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(","),
        allow_credentials=True,
    ),
    csrf_config=CSRFConfig(secret=os.environ["CSRF_SECRET"]),
    allowed_hosts=os.environ.get("ALLOWED_HOSTS", "example.com").split(","),
    session_config=SessionConfig(
        secret=os.environ["SESSION_SECRET"],
        secure=True,
        samesite="lax",
    ),
)
"""


class TestLitestarAnalyzer:
    def test_detects_insecure_litestar_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_LITESTAR_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["litestar>=2.0.0", "httpx>=0.27.0"]\n',
            encoding="utf-8",
        )

        analyzer = LitestarAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "session_secret_hardcoded" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "csrf_disabled" in kinds
        assert "dangerous_route" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = LitestarAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_litestar_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_LITESTAR_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["litestar>=2.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = LitestarAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from litestar import Litestar\napp = Litestar(route_handlers=[])\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["litestar"]\n',
            encoding="utf-8",
        )

        analyzer = LitestarAnalyzer(str(tmp_path))
        assert "Litestar:" in analyzer.summary()
        assert "Litestar application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = LitestarAnalyzer(".").generate_hardened_template()
        assert "Litestar" in template
        assert "CSRFConfig" in template
        assert "os.environ" in template

    def test_finding_format(self):
        finding = LitestarFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "main.py:1" in finding.format()
