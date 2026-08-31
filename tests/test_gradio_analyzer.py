"""Tests for GradioAnalyzer."""

from pathlib import Path

from devai.gradio_analyzer import GradioAnalyzer, GradioFinding


INSECURE_GRADIO_APP = """\
import gradio as gr

API_KEY = "sk-hardcoded-secret-key-value"

def greet(name):
    return name

demo = gr.Interface(fn=greet, inputs="text", outputs="text")
demo.launch(share=True, auth=None, server_name="0.0.0.0", show_api=True)
"""

HARDENED_GRADIO_APP = """\
import os

import gradio as gr


def greet(name: str) -> str:
    return f"Hello, {name}!"


demo = gr.Interface(fn=greet, inputs="text", outputs="text")

if __name__ == "__main__":
    demo.launch(
        auth=(os.environ["GRADIO_USER"], os.environ["GRADIO_PASSWORD"]),
        share=False,
        server_name="127.0.0.1",
        show_api=False,
    )
"""


class TestGradioAnalyzer:
    def test_detects_insecure_gradio_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_GRADIO_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["gradio>=4.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = GradioAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "share_enabled" in kinds
        assert analyzer.health_score() < 80.0

    def test_no_findings_on_clean_project(self, tmp_path: Path):
        analyzer = GradioAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_hardened_gradio_app_scores_well(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_GRADIO_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = ["gradio>=4.0.0"]\n',
            encoding="utf-8",
        )

        analyzer = GradioAnalyzer(str(tmp_path))
        high = [f for f in analyzer.analyze() if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 90.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import gradio as gr\ndemo = gr.Interface(lambda x: x, 'text', 'text')\n",
            encoding="utf-8",
        )
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["gradio"]\n',
            encoding="utf-8",
        )

        analyzer = GradioAnalyzer(str(tmp_path))
        assert "Gradio:" in analyzer.summary()
        assert "Gradio application analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = GradioAnalyzer(".").generate_hardened_template()
        assert "gradio" in template
        assert "GRADIO_USER" in template

    def test_finding_format(self):
        finding = GradioFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "app.py:1" in finding.format()
