"""Tests for StreamlitAnalyzer."""

from pathlib import Path

from devai.streamlit_analyzer import StreamlitAnalyzer, StreamlitFinding


INSECURE_STREAMLIT_APP = """\
import os
import subprocess

import streamlit as st

API_KEY = "sk-hardcoded-openai-key"
OPENAI_API_KEY = "sk-test123456789"

st.set_page_config(page_title="Demo", layout="wide")

user_input = st.text_input("Enter text")
st.markdown(user_input, unsafe_allow_html=True)

uploaded = st.file_uploader("Upload a file")

if st.button("Run"):
    cmd = st.text_input("Command")
    subprocess.run(cmd, shell=True)

st.components.v1.html(f"<div>{user_input}</div>")
"""

INSECURE_STREAMLIT_CONFIG = """\
[server]
address = "0.0.0.0"
enableCORS = true
enableXsrfProtection = false
showErrorDetails = true
enableStaticServing = true
runOnSave = true

[client]
toolbarMode = "developer"
"""

INSECURE_SECRETS_TOML = """\
OPENAI_API_KEY = "sk-live-secret-key-here"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""

HARDENED_STREAMLIT_APP = """\
import os

import streamlit as st


def main() -> None:
    st.set_page_config(page_title="App", layout="wide")
    api_key = os.environ.get("API_KEY") or st.secrets.get("API_KEY", "")
    if not api_key:
        st.error("API_KEY not configured")
        st.stop()
    st.success("Ready")


if __name__ == "__main__":
    main()
"""


class TestStreamlitAnalyzer:
    def test_detects_insecure_streamlit_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_STREAMLIT_APP, encoding="utf-8")
        streamlit_dir = tmp_path / ".streamlit"
        streamlit_dir.mkdir()
        (streamlit_dir / "config.toml").write_text(INSECURE_STREAMLIT_CONFIG, encoding="utf-8")
        (streamlit_dir / "secrets.toml").write_text(INSECURE_SECRETS_TOML, encoding="utf-8")

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}

        assert "hardcoded_secret" in kinds
        assert "unsafe_html" in kinds
        assert "shell_command" in kinds
        assert "xsrf_disabled" in kinds
        assert "secrets_file_committed" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_STREAMLIT_APP, encoding="utf-8")

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_streamlit_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["streamlit>=1.30.0"]\n',
            encoding="utf-8",
        )
        (tmp_path / "app.py").write_text(
            "import streamlit as st\nst.title('Hello')\n",
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert analyzer.stats.configs >= 1

    def test_finding_format(self):
        finding = StreamlitFinding(
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
        template = StreamlitAnalyzer(".").generate_hardened_template()
        assert "import streamlit" in template
        assert "st.secrets" in template
        assert "unsafe_allow_html" not in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_STREAMLIT_APP, encoding="utf-8")

        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert "Streamlit:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Streamlit application analysis:" in context
        assert "health score:" in context

    def test_detects_pages_directory(self, tmp_path: Path):
        pages = tmp_path / "pages"
        pages.mkdir()
        (pages / "settings.py").write_text(
            "import streamlit as st\nst.write('settings')\n",
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        paths = [str(p.relative_to(tmp_path)) for p in analyzer.configs()]
        assert "pages/settings.py" in paths
