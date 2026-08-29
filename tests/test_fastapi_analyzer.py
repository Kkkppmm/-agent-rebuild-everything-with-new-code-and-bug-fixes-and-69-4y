"""Tests for FastAPIAnalyzer."""

from pathlib import Path

from devai.fastapi_analyzer import FastAPIAnalyzer, FastAPIFinding

INSECURE_FASTAPI_APP = """\
import subprocess
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx

app = FastAPI(debug=True, docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
api_key = "api_key=hardcoded_secret_value_12345"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/proxy")
async def proxy():
    client = httpx.AsyncClient(verify=False)
    return await client.get("http://10.0.0.1:8080/internal")

@app.post("/run")
async def run(cmd: str):
    subprocess.run(cmd, shell=True)
    eval(cmd)
    return {"ok": True}

@app.get("/redirect")
async def redirect(request):
    from starlette.responses import RedirectResponse
    return RedirectResponse(request.query_params["url"])

@app.get("/users/{user_id}")
async def users(user_id: str):
  conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""

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


class TestFastAPIAnalyzer:
    def test_detects_insecure_fastapi_app(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_FASTAPI_APP, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "debug_enabled" in kinds
        assert "cors_wildcard" in kinds
        assert "docs_exposed" in kinds
        assert "ssrf_internal" in kinds
        assert "tls_verification_disabled" in kinds
        assert "shell_true" in kinds
        assert "eval_usage" in kinds
        assert "sql_fstring" in kinds
        assert "open_redirect" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_fastapi_app_scores_well(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_FASTAPI_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() >= 90.0

    def test_no_files_returns_empty(self, tmp_path: Path):
        analyzer = FastAPIAnalyzer(str(tmp_path))
        assert analyzer.files() == []
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
        assert "TrustedHostMiddleware" in template
        assert "docs_url" in template
