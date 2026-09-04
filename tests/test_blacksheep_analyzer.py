"""Tests for BlacksheepAnalyzer."""

from pathlib import Path

from devai.blacksheep_analyzer import BlacksheepAnalyzer, BlacksheepFinding


INSECURE_BLACKSHEEP_APP = """\
import os
import subprocess

import uvicorn
from blacksheep import Application
from blacksheep.server.cors import allow_all_origins
from blacksheep.server.responses import redirect

API_KEY = "hardcoded_secret_value"

app = Application()
allow_all_origins(app, allow_credentials=True)


@app.router.get("/admin")
async def admin(request):
    return str(request.headers)


@app.router.get("/run")
async def run_cmd(request):
    cmd = request.query.get("cmd")
    subprocess.run(cmd, shell=True)


@app.router.get("/redirect")
async def go(request):
    return redirect(request.query.get("url"))


@app.router.get("/echo")
async def echo(request):
    return request.query.get("msg")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, reload=True)
"""

HARDENED_BLACKSHEEP_APP = """\
import os

import uvicorn
from blacksheep import Application
from blacksheep.server.responses import json


app = Application()


@app.router.get("/health")
async def health():
    return json({"status": "ok"})


def main() -> None:
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
        reload=False,
    )


if __name__ == "__main__":
    main()
"""


class TestBlacksheepAnalyzer:
    def test_detects_insecure_blacksheep_app(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_BLACKSHEEP_APP, encoding="utf-8")

        analyzer = BlacksheepAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "cors_wildcard" in kinds
        assert "dangerous_route" in kinds
        assert "shell_command" in kinds
        assert "bind_all_interfaces" in kinds
        assert "debug_mode" in kinds
        assert analyzer.health_score() < 50

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(HARDENED_BLACKSHEEP_APP, encoding="utf-8")

        analyzer = BlacksheepAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_blacksheep_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["blacksheep>=2.0.0"]\n',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text(
            "from blacksheep import Application\napp = Application()\n",
            encoding="utf-8",
        )

        analyzer = BlacksheepAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) >= 1

    def test_finding_format(self):
        finding = BlacksheepFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="main.py",
            lineno=5,
            line="SECRET = 'x'",
        )
        assert "[high]" in finding.format()
        assert "main.py:5" in finding.format()

    def test_generate_hardened_template(self):
        template = BlacksheepAnalyzer(".").generate_hardened_template()
        assert "Application()" in template
        assert "reload=False" in template
        assert "127.0.0.1" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_BLACKSHEEP_APP, encoding="utf-8")

        analyzer = BlacksheepAnalyzer(str(tmp_path))
        assert "BlackSheep:" in analyzer.summary()
        context = analyzer.to_context()
        assert "BlackSheep application analysis:" in context
        assert "health score:" in context
