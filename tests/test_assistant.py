"""Tests for DevAI assistant."""

import pytest

from devai import CodeAssistant
from devai.core import MockLLMClient

SAMPLE_CODE = "def add(a, b):\n    return a + b"


class TestCodeAssistant:
    @pytest.fixture
    def assistant(self):
        client = MockLLMClient(default_response="Analysis complete.")
        return CodeAssistant(client=client)

    def test_review(self, assistant):
        result = assistant.review(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_explain(self, assistant):
        result = assistant.explain(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_debug(self, assistant):
        result = assistant.debug(SAMPLE_CODE, "TypeError")
        assert result == "Analysis complete."

    def test_refactor(self, assistant):
        result = assistant.refactor(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_security(self, assistant):
        result = assistant.security(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_tests(self, assistant):
        result = assistant.tests(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_docstring(self, assistant):
        result = assistant.docstring(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_commit_message(self, assistant):
        result = assistant.commit_message("diff content")
        assert result == "Analysis complete."

    def test_pr_description(self, assistant):
        result = assistant.pr_description("Fix bug", "diff")
        assert result == "Analysis complete."

    def test_changelog(self, assistant):
        result = assistant.changelog("1.0.0", "Added feature X")
        assert result == "Analysis complete."

    def test_translate_code(self, assistant):
        result = assistant.translate_code(SAMPLE_CODE, "python", "javascript")
        assert result == "Analysis complete."

    def test_add_error_handling(self, assistant):
        result = assistant.add_error_handling(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_api_design(self, assistant):
        result = assistant.api_design(SAMPLE_CODE, context="REST API")
        assert result == "Analysis complete."

    def test_optimize_sql(self, assistant):
        result = assistant.optimize_sql("SELECT * FROM users", context="users table")
        assert result == "Analysis complete."

    def test_readme(self, assistant):
        result = assistant.readme("MyApp", "A cool app")
        assert result == "Analysis complete."

    def test_type_hints(self, assistant):
        result = assistant.type_hints(SAMPLE_CODE)
        assert result == "Analysis complete."

    def test_regex(self, assistant):
        result = assistant.regex("match email addresses", test_cases="a@b.com")
        assert result == "Analysis complete."

    def test_analyze_logs(self, assistant):
        result = assistant.analyze_logs("ERROR: connection refused")
        assert result == "Analysis complete."

    def test_review_project(self, assistant, tmp_path):
        (tmp_path / "app.py").write_text(SAMPLE_CODE)
        result = assistant.review_project(str(tmp_path))
        assert result == "Analysis complete."

    def test_review_file(self, assistant, tmp_path):
        f = tmp_path / "test.py"
        f.write_text(SAMPLE_CODE)
        result = assistant.review_file(str(f))
        assert result == "Analysis complete."

    def test_review_directory(self, assistant, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.py").write_text("y = 2")
        result = assistant.review_directory(str(tmp_path))
        assert "a.py" in result

    def test_full_review(self, assistant):
        results = assistant.full_review(SAMPLE_CODE)
        assert "review" in results
        assert "security" in results
        assert "docstrings" in results

    def test_stream_explain(self, assistant):
        chunks = list(assistant.stream_explain(SAMPLE_CODE))
        assert len(chunks) > 0

    @pytest.mark.asyncio
    async def test_areview(self, assistant):
        result = await assistant.areview(SAMPLE_CODE)
        assert result == "Analysis complete."
