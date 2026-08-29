"""Tests for FastAPIAnalyzer."""

from pathlib import Path

from devai.fastapi_analyzer import FastAPIAnalyzer, FastAPIFinding


INSECURE_APP = '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx

API_KEY = "sk-live-hardcoded-secret-key"
app = FastAPI(debug=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)

@app.get("/proxy")
async def proxy(url: str):
    return await httpx.get(url)
'''

HARDENED_APP = '''
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    debug=False,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.environ.get("ALLOWED_HOSTS", "example.com").split(","),
)
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
)


@app.get("/health")
async def health():
    return {"status": "ok"}
'''


class TestFastAPIAnalyzer:
    def test_no_fastapi_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        assert analyzer.stats.fastapi_files == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "debug_enabled" in kinds
        assert "cors_wildcard" in kinds
        assert "cors_credentials_wildcard" in kinds
        assert "ssrf_user_url" in kinds
        assert "openapi_docs_exposed" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_app_scores_well(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.routes == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_APP, encoding="utf-8")
        analyzer = FastAPIAnalyzer(str(tmp_path))
        assert "FastAPI" in analyzer.summary()
        assert "FastAPI analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "TrustedHostMiddleware" in template

    def test_finding_format(self):
        finding = FastAPIFinding(
            kind="debug_enabled",
            severity="high",
            message="debug on",
            path="main.py",
            lineno=5,
            line="app = FastAPI(debug=True)",
        )
        assert "main.py:5" in finding.format()
