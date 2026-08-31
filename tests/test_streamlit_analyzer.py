"""Tests for StreamlitAnalyzer."""

from pathlib import Path

from devai.streamlit_analyzer import StreamlitAnalyzer, StreamlitFinding


INSECURE_STREAMLIT_APP = """\
import os
import subprocess

import streamlit as st
import streamlit.components.v1 as components

API_KEY = "sk-hardcoded-openai-key"
password = "admin123"

st.set_page_config(page_title="Insecure App")

user_html = st.text_input("HTML")
st.markdown(user_html, unsafe_allow_html=True)

uploaded = st.file_uploader("Upload any file")

if st.button("Run"):
    cmd = st.session_state.get("cmd")
    subprocess.check_output(cmd, shell=True)

if st.button("Fetch"):
    import requests
    st.write(requests.get("http://192.168.1.10/api", verify=False).text)

components.v1.iframe(st.session_state.get("url"))
"""

HARDENED_STREAMLIT_APP = """\
import os

import streamlit as st


def main() -> None:
    st.set_page_config(page_title="Secure App", layout="wide")
    api_key = st.secrets.get("API_KEY", os.environ.get("API_KEY"))
    st.title("Secure Streamlit App")
    user_input = st.text_input("Enter text")
    if user_input:
        st.markdown(user_input)


if __name__ == "__main__":
    main()
"""


class TestStreamlitAnalyzer:
    def test_detects_insecure_streamlit_app(self, tmp_path: Path):
        (tmp_path / "streamlit_app.py").write_text(INSECURE_STREAMLIT_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["streamlit>=1.30.0"]\n',
            encoding="utf-8",
        )
        streamlit_dir = tmp_path / ".streamlit"
        streamlit_dir.mkdir()
        (streamlit_dir / "config.toml").write_text(
            "server.enableXsrfProtection = false\nserver.address = \"0.0.0.0\"\n",
            encoding="utf-8",
        )
        (streamlit_dir / "secrets.toml").write_text(
            'API_KEY = "committed-secret-value"\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unsafe_html" in kinds
        assert "xsrf_disabled" in kinds or "committed_secrets" in kinds
        assert "ssrf_internal" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_streamlit_app_scores_well(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_STREAMLIT_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["streamlit>=1.30.0"]\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "streamlit_app.py").write_text(
            "import streamlit as st\nst.title('Hello')\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["streamlit"]\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert "Streamlit:" in analyzer.summary()
        assert "Streamlit application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = StreamlitAnalyzer(".").generate_hardened_template()
        assert "streamlit" in template
        assert "st.secrets" in template
        assert "unsafe_allow_html" in template

    def test_finding_format(self):
        finding = StreamlitFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()
