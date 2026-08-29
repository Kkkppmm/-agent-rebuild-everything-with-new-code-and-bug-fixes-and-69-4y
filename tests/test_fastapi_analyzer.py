"""Tests for FastAPIAnalyzer."""

from pathlib import Path

from devai.fastapi_analyzer import FastAPIAnalyzer, FastAPIFinding


INSECURE_FASTAPI_APP = """\
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn

API_KEY = 'hardcoded_api_key_secret_12345'
WEBHOOK = 'http://10.0.0.5/internal/hook'

app = FastAPI(
    title="API",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def fetch():
  async with httpx.AsyncClient(verify=False) as client:
      return await client.get(WEBHOOK)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
"""

HARDENED_FASTAPI_APP = """\
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

DEBUG = os.environ.get("FASTAPI_DEBUG", "false").lower() == "true"

app = FastAPI(
    title="API",
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
"""


class TestFastAPIAnalyzer:
    def test_detects_insecure_fastapi_app(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_FASTAPI_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "cors_wildcard" in kinds
        assert "docs_exposed" in kinds
        assert "internal_url" in kinds
        assert "tls_verification_disabled" in kinds
        assert "uvicorn_reload" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_fastapi_app_scores_well(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_app_returns_empty(self, tmp_path: Path):
        analyzer = FastAPIAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no application" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = FastAPIFinding(
            kind="test",
            severity="high",
            message="test message",
            path="main.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "FastAPI application analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = FastAPIAnalyzer(".").generate_hardened_template()
        assert "docs_url=\"/docs\" if DEBUG else None" in template
        assert "allow_origins=os.environ" in template
