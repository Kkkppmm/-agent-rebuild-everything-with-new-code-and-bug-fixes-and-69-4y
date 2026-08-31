"""Tests for ChainlitAnalyzer."""

from pathlib import Path

from devai.chainlit_analyzer import ChainlitAnalyzer, ChainlitFinding


INSECURE_CHAINLIT_APP = """\
import os
import subprocess

import chainlit as cl

CHAINLIT_AUTH_SECRET = "hardcoded_auth_secret"
API_KEY = "hardcoded_secret_value"


@cl.on_chat_start
async def start():
    await cl.Message(content=str(os.environ)).send()
    await cl.AskFileMessage(content="Upload").send()


@cl.on_message
async def on_message(message: cl.Message):
    subprocess.run(message.content, shell=True)
"""

HARDENED_CHAINLIT_APP = """\
import os

import chainlit as cl


@cl.password_auth_callback
def auth_callback(username: str, password: str):
    if username == os.environ.get("CHAINLIT_USER") and password == os.environ.get("CHAINLIT_PASSWORD"):
        return cl.User(identifier=username)
    return None


@cl.on_chat_start
async def start():
    await cl.Message(content="Authenticated session started.").send()
"""


class TestChainlitAnalyzer:
    def test_detects_insecure_chainlit_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_CHAINLIT_APP, encoding="utf-8")

        analyzer = ChainlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "auth_secret_hardcoded" in kinds
        assert "missing_auth" in kinds
        assert "file_upload_unrestricted" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 50

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_CHAINLIT_APP, encoding="utf-8")

        analyzer = ChainlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_chainlit_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["chainlit>=1.0.0"]\n',
            encoding="utf-8",
        )
        (tmp_path / "app.py").write_text(
            "import chainlit as cl\n@cl.on_chat_start\nasync def start(): pass\n",
            encoding="utf-8",
        )

        analyzer = ChainlitAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) >= 1

    def test_finding_format(self):
        finding = ChainlitFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="app.py",
            lineno=5,
            line="SECRET = 'x'",
        )
        assert "[high]" in finding.format()
        assert "app.py:5" in finding.format()

    def test_generate_hardened_template(self):
        template = ChainlitAnalyzer(".").generate_hardened_template()
        assert "chainlit" in template
        assert "password_auth_callback" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_CHAINLIT_APP, encoding="utf-8")

        analyzer = ChainlitAnalyzer(str(tmp_path))
        assert "Chainlit:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Chainlit application analysis:" in context
        assert "health score:" in context
