"""Tests for GradioAnalyzer."""

from pathlib import Path

from devai.gradio_analyzer import GradioAnalyzer, GradioFinding


INSECURE_GRADIO_APP = """\
import os
import subprocess

import gradio as gr

API_KEY = "hardcoded_secret_value"


def predict(text):
    subprocess.run(text, shell=True)
    return text


demo = gr.Interface(fn=predict, inputs="text", outputs="text")
demo.launch(share=True, server_name="0.0.0.0", api_open=True)
"""

HARDENED_GRADIO_APP = """\
import os

import gradio as gr


def predict(text: str) -> str:
    return text


def main() -> None:
    demo = gr.Interface(fn=predict, inputs="text", outputs="text")
    demo.launch(
        server_name=os.environ.get("HOST", "127.0.0.1"),
        share=False,
        auth=(os.environ["GRADIO_USER"], os.environ["GRADIO_PASSWORD"]),
        api_open=False,
    )


if __name__ == "__main__":
    main()
"""


class TestGradioAnalyzer:
    def test_detects_insecure_gradio_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_GRADIO_APP, encoding="utf-8")

        analyzer = GradioAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "share_enabled" in kinds
        assert "missing_auth" in kinds
        assert "api_open" in kinds
        assert "server_name_all" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 50

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_GRADIO_APP, encoding="utf-8")

        analyzer = GradioAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_gradio_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["gradio>=4.0.0"]\n',
            encoding="utf-8",
        )
        (tmp_path / "demo.py").write_text(
            "import gradio as gr\ndemo = gr.Interface(lambda x: x, 'text', 'text')\n",
            encoding="utf-8",
        )

        analyzer = GradioAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) >= 1

    def test_finding_format(self):
        finding = GradioFinding(
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
        template = GradioAnalyzer(".").generate_hardened_template()
        assert "gradio" in template
        assert "share=False" in template
        assert "auth=" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_GRADIO_APP, encoding="utf-8")

        analyzer = GradioAnalyzer(str(tmp_path))
        assert "Gradio:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Gradio application analysis:" in context
        assert "health score:" in context
