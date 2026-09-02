"""Tests for ChainlitAnalyzer."""

from pathlib import Path

from devai.chainlit_analyzer import ChainlitAnalyzer, ChainlitFinding


INSECURE_CHAINLIT_APP = """\
import os
import subprocess

import chainlit as cl

API_KEY = "sk-hardcoded-openai-key"
CHAINLIT_AUTH_SECRET = "super-secret-auth-key"

@cl.on_chat_start
async def on_chat_start():
    await cl.Message(content="Welcome").send()

@cl.on_message
async def on_message(message: cl.Message):
    subprocess.run(message.content, shell=True)
    await cl.Markdown(content=f"<div>{message.content}</div>").send()

@cl.action_callback("run")
async def on_action(action):
    eval(action.payload)
"""

INSECURE_CHAINLIT_CONFIG = """\
[project]
enable_telemetry = false

[features]
spontaneous_file_upload = { enabled = true }

[UI]
"""

INSECURE_CHAINLIT_SECRETS = """\
OPENAI_API_KEY = "sk-live-secret-key-here"
CHAINLIT_AUTH_SECRET = "committed-secret-value"
"""

HARDENED_CHAINLIT_APP = """\
import os

import chainlit as cl


@cl.password_auth_callback
def auth_callback(username: str, password: str):
    valid_user = os.environ.get("CHAINLIT_USER", "")
    valid_pass = os.environ.get("CHAINLIT_PASSWORD", "")
    if username == valid_user and password == valid_pass:
        return cl.User(identifier=username, metadata={"role": "user"})
    return None


@cl.on_chat_start
async def on_chat_start():
    await cl.Message(content="Welcome!").send()


@cl.on_message
async def on_message(message: cl.Message):
    user_text = (message.content or "").strip()
    if not user_text or len(user_text) > 10_000:
        await cl.Message(content="Invalid input.").send()
        return
    await cl.Message(content=f"Processed: {user_text[:500]}").send()
"""


class TestChainlitAnalyzer:
    def test_detects_insecure_chainlit_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_CHAINLIT_APP, encoding="utf-8")
        chainlit_dir = tmp_path / ".chainlit"
        chainlit_dir.mkdir()
        (chainlit_dir / "config.toml").write_text(INSECURE_CHAINLIT_CONFIG, encoding="utf-8")
        (chainlit_dir / "secrets.toml").write_text(INSECURE_CHAINLIT_SECRETS, encoding="utf-8")

        analyzer = ChainlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}

        assert "hardcoded_secret" in kinds
        assert "shell_command" in kinds
        assert "eval_exec" in kinds
        assert "missing_auth" in kinds
        assert "secrets_file_committed" in kinds
        assert analyzer.health_score() < 50.0

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
            "import chainlit as cl\n\n@cl.on_message\nasync def on_message(msg): pass\n",
            encoding="utf-8",
        )

        analyzer = ChainlitAnalyzer(str(tmp_path))
        assert analyzer.stats.configs >= 1

    def test_finding_format(self):
        finding = ChainlitFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="app.py",
            lineno=5,
            line="API_KEY = 'secret'",
        )
        assert "[high]" in finding.format()
        assert "app.py:5" in finding.format()

    def test_generate_hardened_template(self):
        template = ChainlitAnalyzer(".").generate_hardened_template()
        assert "import chainlit" in template
        assert "password_auth_callback" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_CHAINLIT_APP, encoding="utf-8")

        analyzer = ChainlitAnalyzer(str(tmp_path))
        context = analyzer.to_context()

        assert "Chainlit application analysis:" in context
        assert "health score:" in context

    def test_detects_cors_wildcard_in_config(self, tmp_path: Path):
        chainlit_dir = tmp_path / ".chainlit"
        chainlit_dir.mkdir()
        (chainlit_dir / "config.toml").write_text(
            '[project]\nname = "demo"\n\n[features]\nallow_origins = ["*"]\n',
            encoding="utf-8",
        )
        (tmp_path / "app.py").write_text(
            "import chainlit as cl\n@cl.on_message\nasync def on_message(msg): pass\n",
            encoding="utf-8",
        )

        analyzer = ChainlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}

        assert "cors_wildcard" in kinds
