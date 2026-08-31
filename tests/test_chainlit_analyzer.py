"""Tests for ChainlitAnalyzer."""

from pathlib import Path

from devai.chainlit_analyzer import ChainlitAnalyzer, ChainlitFinding


INSECURE_CHAINLIT_APP = """\
import os
import subprocess

import chainlit as cl

API_KEY = "hardcoded-secret-value"


@cl.on_message
async def main(message: cl.Message):
    subprocess.run(message.content, shell=True)
    await cl.Message(content=message.content).send()
"""

HARDENED_CHAINLIT_APP = """\
import os

import chainlit as cl


@cl.password_auth_callback
def auth_callback(username: str, password: str):
    if username == os.environ.get("CHAINLIT_USER"):
        return cl.User(identifier=username)
    return None


@cl.on_message
async def main(message: cl.Message):
    await cl.Message(content=message.content).send()
"""


class TestChainlitAnalyzer:
    def test_detects_insecure_chainlit_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_CHAINLIT_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["chainlit>=1.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = ChainlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "missing_auth" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = ChainlitAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_chainlit_app_scores_well(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_CHAINLIT_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["chainlit"]\n',
            encoding="utf-8",
        )

        analyzer = ChainlitAnalyzer(str(tmp_path))
        high = [f for f in analyzer.analyze() if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import chainlit as cl\n@cl.on_message\nasync def main(m): pass\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["chainlit"]\n',
            encoding="utf-8",
        )

        analyzer = ChainlitAnalyzer(str(tmp_path))
        assert "Chainlit:" in analyzer.summary()
        assert "Chainlit application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = ChainlitFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
            line="SECRET = 'x'",
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()

    def test_generate_hardened_template(self):
        template = ChainlitAnalyzer(".").generate_hardened_template()
        assert "chainlit" in template
        assert "password_auth_callback" in template
