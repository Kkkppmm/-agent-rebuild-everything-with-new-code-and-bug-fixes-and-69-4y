"""Tests for FastAPIAnalyzer."""

from pathlib import Path

from devai.fastapi_analyzer import FastAPIAnalyzer, FastAPIFinding


INSECURE_FASTAPI_APP = """\
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx

SECRET_KEY = "hardcoded_secret_value"
JWT_SECRET = "jwt_secret_123"

app = FastAPI(
    title="API",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/admin/users")
def admin_users():
    return []


@app.get("/debug/env")
def debug_env():
    return os.environ


@app.get("/proxy")
async def proxy(url: str):
    async with httpx.AsyncClient(verify=False) as client:
        return await client.get("http://192.168.1.10/api")
"""

HARDENED_FASTAPI_APP = """\
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str
    allowed_origins: list[str] = ["https://example.com"]
    allowed_hosts: list[str] = ["example.com"]

    model_config = {"env_file": ".env"}


settings = Settings()

app = FastAPI(
    title="API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}
"""


class TestFastAPIAnalyzer:
    def test_detects_insecure_fastapi_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_FASTAPI_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["fastapi>=0.100.0", "httpx>=0.27.0"]\n',
            encoding="utf-8",
        )

        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "jwt_secret_hardcoded" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "dangerous_route" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = FastAPIAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_fastapi_app_scores_well(self, tmp_path: Path):
        app_dir = tmp_path / "src"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["fastapi>=0.100.0", "pydantic-settings>=2.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            "from fastapi import FastAPI\napp = FastAPI()\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["fastapi"]\n',
            encoding="utf-8",
        )

        analyzer = FastAPIAnalyzer(str(tmp_path))
        assert "FastAPI:" in analyzer.summary()
        assert "FastAPI application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = FastAPIAnalyzer(".").generate_hardened_template()
        assert "FastAPI" in template
        assert "TrustedHostMiddleware" in template
        assert "docs_url=None" in template

    def test_finding_format(self):
        finding = FastAPIFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "main.py:1" in finding.format()
