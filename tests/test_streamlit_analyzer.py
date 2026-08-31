"""Tests for StreamlitAnalyzer."""

from pathlib import Path

from devai.streamlit_analyzer import StreamlitAnalyzer, StreamlitFinding


INSECURE_STREAMLIT_APP = """\
import os
import subprocess

import streamlit as st

API_KEY = "hardcoded_secret_value"

st.set_page_config(page_title="Demo")
st.markdown(user_input, unsafe_allow_html=True)
st.write(os.environ)
uploaded = st.file_uploader("Upload")
subprocess.run("ls", shell=True)
"""

HARDENED_STREAMLIT_APP = """\
import os

import streamlit as st


st.set_page_config(page_title="Secure App")


def main() -> None:
    api_key = os.environ.get("API_KEY")
    if not api_key:
        st.error("API_KEY required")
        st.stop()
    st.success("Ready")


if __name__ == "__main__":
    main()
"""


class TestStreamlitAnalyzer:
    def test_detects_insecure_streamlit_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_STREAMLIT_APP, encoding="utf-8")

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unsafe_allow_html" in kinds
        assert "env_exposed" in kinds
        assert "file_uploader_unrestricted" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 50

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
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text(
            "import streamlit as st\nst.title('hi')\n",
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) >= 1

    def test_detects_config_secrets(self, tmp_path: Path):
        config_dir = tmp_path / ".streamlit"
        config_dir.mkdir()
        (config_dir / "secrets.toml").write_text(
            'api_key = "committed_secret"\n',
            encoding="utf-8",
        )
        (tmp_path / "app.py").write_text(
            "import streamlit as st\nst.title('hi')\n",
            encoding="utf-8",
        )

        analyzer = StreamlitAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "committed_secret" for f in findings)

    def test_finding_format(self):
        finding = StreamlitFinding(
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
        template = StreamlitAnalyzer(".").generate_hardened_template()
        assert "streamlit" in template
        assert "os.environ" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_STREAMLIT_APP, encoding="utf-8")

        analyzer = StreamlitAnalyzer(str(tmp_path))
        assert "Streamlit:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Streamlit application analysis:" in context
        assert "health score:" in context
