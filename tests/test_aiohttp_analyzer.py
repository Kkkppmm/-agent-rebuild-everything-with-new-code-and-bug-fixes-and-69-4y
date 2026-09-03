"""Tests for AiohttpAnalyzer."""

from pathlib import Path

from devai.aiohttp_analyzer import AiohttpAnalyzer, AiohttpFinding


INSECURE_AIOHTTP_APP = """\
import os
import subprocess
from aiohttp import web
import aiohttp_cors

SECRET_KEY = "hardcoded_secret_value"
app = web.Application(debug=True)


async def admin_users(request):
    return web.json_response([])


async def debug_env(request):
    return web.json_response(dict(os.environ))


async def run_cmd(request):
    cmd = request.query.get("cmd")
    return web.Response(text=subprocess.check_output(cmd, shell=True).decode())


async def proxy(request):
  import aiohttp
  async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
      async with session.get("http://192.168.1.10/api") as resp:
          return web.Response(text=await resp.text())


cors = aiohttp_cors.setup(app, defaults={
    "*": aiohttp_cors.ResourceOptions(allow_credentials=True, expose_headers="*"),
})

app.router.add_get("/admin/users", admin_users)
app.router.add_get("/debug/env", debug_env)
app.router.add_get("/run", run_cmd)
app.router.add_get("/proxy", proxy)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8080)
"""

HARDENED_AIOHTTP_APP = """\
import os
from aiohttp import web
import aiohttp_cors


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def create_app() -> web.Application:
    app = web.Application()
    cors = aiohttp_cors.setup(
        app,
        defaults={
            origin: aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
            )
            for origin in os.environ.get("ALLOWED_ORIGINS", "https://example.com").split(",")
        },
    )
    app.router.add_get("/health", health)
    for route in list(app.router.routes()):
        cors.add(route)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="127.0.0.1", port=8080)
"""


class TestAiohttpAnalyzer:
    def test_detects_insecure_aiohttp_app(self, tmp_path: Path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "main.py").write_text(INSECURE_AIOHTTP_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["aiohttp>=3.9.0", "aiohttp-cors>=0.7.0"]\n',
            encoding="utf-8",
        )

        analyzer = AiohttpAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "cors_wildcard" in kinds or "cors_credentials_wildcard" in kinds
        assert "dangerous_route" in kinds
        assert "shell_command" in kinds
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
            'dependencies = ["aiohttp>=3.9.0", "aiohttp-cors>=0.7.0"]\n',
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
        assert "aiohttp:" in analyzer.summary()
        assert "aiohttp application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = AiohttpAnalyzer(".").generate_hardened_template()
        assert "web.Application" in template
        assert "aiohttp_cors" in template
        assert "ALLOWED_ORIGINS" in template

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
