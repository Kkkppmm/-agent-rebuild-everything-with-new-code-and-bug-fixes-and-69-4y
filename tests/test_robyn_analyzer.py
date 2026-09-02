"""Tests for RobynAnalyzer."""

from pathlib import Path

from devai.robyn_analyzer import RobynAnalyzer, RobynFinding


INSECURE_ROBYN_APP = """\
import os
import subprocess

from robyn import Robyn, Request, ALLOW_CORS

API_KEY = "hardcoded_secret_value"

app = Robyn(__file__)
ALLOW_CORS(app, origins=["*"], allow_credentials=True)


@app.get("/admin")
async def admin(request: Request):
    return str(request.headers)


@app.get("/run")
async def run_cmd(request: Request):
    cmd = request.query_params.get("cmd")
    subprocess.run(cmd, shell=True)


@app.get("/redirect")
async def go(request: Request):
    return Response(status_code=302, headers={"Location": request.query_params.get("url")})


@app.get("/echo")
async def echo(request: Request):
    return request.query_params.get("msg")


if __name__ == "__main__":
    app.start(host="0.0.0.0", port=8080, debug=True, reloader=True)
"""

HARDENED_ROBYN_APP = """\
import os

from robyn import Robyn, Request


app = Robyn(__file__)


@app.get("/health")
async def health(_request: Request):
    return {"status": "ok"}


def main() -> None:
    app.start(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
        debug=False,
    )


if __name__ == "__main__":
    main()
"""


class TestRobynAnalyzer:
    def test_detects_insecure_robyn_app(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_ROBYN_APP, encoding="utf-8")

        analyzer = RobynAnalyzer(str(tmp_path))
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
        (tmp_path / "main.py").write_text(HARDENED_ROBYN_APP, encoding="utf-8")

        analyzer = RobynAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_robyn_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["robyn>=0.40.0"]\n',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text(
            "from robyn import Robyn\napp = Robyn(__file__)\n",
            encoding="utf-8",
        )

        analyzer = RobynAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) >= 1

    def test_finding_format(self):
        finding = RobynFinding(
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
        template = RobynAnalyzer(".").generate_hardened_template()
        assert "Robyn(__file__)" in template
        assert "debug=False" in template
        assert "127.0.0.1" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(INSECURE_ROBYN_APP, encoding="utf-8")

        analyzer = RobynAnalyzer(str(tmp_path))
        assert "Robyn:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Robyn application analysis:" in context
        assert "health score:" in context
