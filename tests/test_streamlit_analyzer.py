"""Tests for StreamlitAnalyzer."""

from pathlib import Path

from devai.streamlit_analyzer import StreamlitAnalyzer, StreamlitFinding


INSECURE_STREAMLIT_APP = """\
import os
import subprocess

import streamlit as st

OPENAI_API_KEY = "sk-hardcoded-key-12345"


def main():
    user_html = st.text_input("HTML")
    st.markdown(user_html, unsafe_allow_html=True)
    subprocess.run(st.text_input("cmd"), shell=True)


if __name__ == "__main__":
    main()
"""

HARDENED_STREAMLIT_APP = """\
import os

import streamlit as st


def main():
    api_key = st.secrets.get("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        st.error("Missing API key")
        st.stop()
    st.write("Ready")


if __name__ == "__main__":
    main()
"""


class TestStreamlitAnalyzer:
    def test_detects_insecure_streamlit_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_STREAMLIT_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["streamlit>=1.30.0"]\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unsafe_html" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 80.0

    def test_detects_committed_secrets(self, tmp_path: Path):
        secrets_dir = tmp_path / ".streamlit"
        secrets_dir.mkdir()
        (secrets_dir / "secrets.toml").write_text(
            'OPENAI_API_KEY = "sk-live-secret"\n',
            encoding="utf-8",
        )
        (tmp_path / "app.py").write_text(
            "import streamlit as st\nst.title('hi')\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["streamlit"]\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "committed_secret" for f in findings)

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_streamlit_app_scores_well(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_STREAMLIT_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["streamlit"]\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        high = [f for f in analyzer.analyze() if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import streamlit as st\nst.title('hello')\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["streamlit"]\n',
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert "Streamlit:" in analyzer.summary()
        assert "Streamlit application analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = StreamlitFinding(
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
        template = StreamlitAnalyzer(".").generate_hardened_template()
        assert "streamlit" in template
        assert "st.secrets" in template
