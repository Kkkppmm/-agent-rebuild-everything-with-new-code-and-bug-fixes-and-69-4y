"""Tests for GradioAnalyzer."""

from pathlib import Path

from devai.gradio_analyzer import GradioAnalyzer, GradioFinding


INSECURE_GRADIO_APP = """\
import os
import subprocess

import gradio as gr

API_KEY = "sk-hardcoded-openai-key"
HF_TOKEN = "hf_test123456789"

def predict(text):
    return text

with gr.Blocks() as demo:
    user_input = gr.Textbox(label="Input")
    output = gr.HTML(f"<div>{user_input}</div>")
    uploaded = gr.File(label="Upload")
    btn = gr.Button("Run")
    btn.click(lambda x: subprocess.run(x, shell=True), inputs=user_input, outputs=output)

demo.launch(share=True, server_name="0.0.0.0", auth=None, debug=True, show_api=True)
"""

INSECURE_GRADIO_SECRETS = """\
OPENAI_API_KEY = "sk-live-secret-key-here"
HF_TOKEN = "hf_secret_token_value"
"""

HARDENED_GRADIO_APP = """\
import os

import gradio as gr


def process_input(text: str) -> str:
    if not text:
        return "Invalid input"
    return f"Processed: {text[:500]}"


def main() -> None:
    api_key = os.environ.get("API_KEY", "")
    if not api_key:
        raise RuntimeError("API_KEY required")

    with gr.Blocks(title="Secure App") as demo:
        input_box = gr.Textbox(label="Input")
        output_box = gr.Textbox(label="Output", interactive=False)
        submit = gr.Button("Submit")
        submit.click(process_input, inputs=input_box, outputs=output_box)

    demo.launch(server_name="127.0.0.1", share=False, debug=False, api_open=False)


if __name__ == "__main__":
    main()
"""


class TestGradioAnalyzer:
    def test_detects_insecure_gradio_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_GRADIO_APP, encoding="utf-8")
        gradio_dir = tmp_path / ".gradio"
        gradio_dir.mkdir()
        (gradio_dir / "secrets.toml").write_text(INSECURE_GRADIO_SECRETS, encoding="utf-8")

        analyzer = GradioAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}

        assert "hardcoded_secret" in kinds
        assert "share_enabled" in kinds
        assert "shell_command" in kinds
        assert "secrets_file_committed" in kinds
        assert analyzer.health_score() < 50.0

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
        (tmp_path / "app.py").write_text(
            "import gradio as gr\ngr.Interface(fn=lambda x: x, inputs='text', outputs='text').launch()\n",
            encoding="utf-8",
        )

        analyzer = GradioAnalyzer(str(tmp_path))
        assert analyzer.stats.configs >= 1

    def test_finding_format(self):
        finding = GradioFinding(
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
        template = GradioAnalyzer(".").generate_hardened_template()
        assert "import gradio" in template
        assert "share=False" in template
        assert "share=True" not in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_GRADIO_APP, encoding="utf-8")

        analyzer = GradioAnalyzer(str(tmp_path))
        assert "Gradio:" in analyzer.summary()
        context = analyzer.to_context()
        assert "Gradio application analysis:" in context
        assert "health score:" in context

    def test_detects_demo_entry_file(self, tmp_path: Path):
        (tmp_path / "demo.py").write_text(
            "import gradio as gr\ngr.ChatInterface(fn=lambda m, h: m).launch()\n",
            encoding="utf-8",
        )

        analyzer = GradioAnalyzer(str(tmp_path))
        paths = [str(p.relative_to(tmp_path)) for p in analyzer.configs()]
        assert "demo.py" in paths
