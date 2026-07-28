"""Tests for DevAI CI helpers."""

from devai import CodeAssistant, MockLLMClient
from devai.ci import (
    CIAnnotation,
    ci_gate_passed,
    extract_annotations,
    format_actions_annotations,
    format_actions_summary,
    format_pr_comment,
    write_step_summary,
)
from devai.program import ProgramResult


class TestCIHelpers:
    def _results(self) -> list[ProgramResult]:
        return [
            ProgramResult(
                name="security",
                action="security",
                output="[high] auth.py:42 - SQL injection vulnerability",
            ),
            ProgramResult(
                name="review",
                action="review",
                output="Looks good overall.",
            ),
        ]

    def test_format_pr_comment(self):
        comment = format_pr_comment(self._results(), program_name="ci-gate")
        assert "## DevAI CI Report" in comment
        assert "ci-gate" in comment
        assert "SQL injection" in comment

    def test_format_actions_summary(self):
        summary = format_actions_summary(self._results())
        assert "# DevAI CI Summary" in summary
        assert "security" in summary

    def test_extract_annotations(self):
        annotations = extract_annotations(self._results())
        assert len(annotations) == 1
        assert annotations[0].file == "auth.py"
        assert annotations[0].line == 42
        assert annotations[0].level == "error"

    def test_format_actions_annotations(self):
        annotations = [CIAnnotation(level="error", message="test", file="app.py", line=1)]
        output = format_actions_annotations(annotations)
        assert "::error file=app.py,line=1::test" in output

    def test_ci_gate_passed(self):
        assert ci_gate_passed(self._results()) is False
        ok = [ProgramResult(name="review", action="review", output="All clear.")]
        assert ci_gate_passed(ok) is True

    def test_write_step_summary(self, tmp_path):
        path = tmp_path / "summary.md"
        write_step_summary("# Report\n", path=str(path))
        assert path.read_text() == "# Report\n"

    def test_ci_gate_preset(self):
        from devai import get_preset

        assistant = CodeAssistant(client=MockLLMClient(default_response="ok"))
        program = get_preset("ci-gate", assistant)
        results = program.run({"code": "x=1", "diff": "diff --git a/x.py"})
        assert len(results) == 3
        assert results[0].action == "review_diff"
