"""Tests for v7.68.0 FastAPIAnalyzer integration."""

from pathlib import Path

from devai import DevAI, FastAPIAnalyzer
from devai.project_health import ProjectHealth

HARDENED_FASTAPI_APP = """\
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address

DEBUG = os.getenv("DEBUG", "false").lower() == "true"

app = FastAPI(
    debug=DEBUG,
    docs_url="/docs" if DEBUG else None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.example.com"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization"],
)

limiter = Limiter(key_func=get_remote_address)

@app.get("/health")
@limiter.limit("10/minute")
async def health():
    return {"status": "ok"}
"""


class TestV768FastAPIIntegration:
    def test_facade_fastapi(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        analyzer = DevAI.mock().fastapi(tmp_path)
        assert isinstance(analyzer, FastAPIAnalyzer)
        assert analyzer.stats.files == 1

    def test_project_health_includes_fastapi_category(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        report = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in report.categories}
        assert "fastapi" in names

    def test_public_exports(self):
        from devai import FastAPIFinding, FastAPIInfo, FastAPIStats

        assert FastAPIAnalyzer is not None
        assert FastAPIFinding is not None
        assert FastAPIInfo is not None
        assert FastAPIStats is not None
