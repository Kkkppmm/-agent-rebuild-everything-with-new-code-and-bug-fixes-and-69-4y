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

    def test_review_diff(self, assistant):
        result = assistant.review_diff("diff --git a/foo.py")
        assert result == "Analysis complete."

    def test_performance(self, assistant):
        result = assistant.performance(SAMPLE_CODE, context="high traffic API")
        assert result == "Analysis complete."

    def test_dockerfile(self, assistant):
        result = assistant.dockerfile("FROM python:3.12")
        assert result == "Analysis complete."

    def test_migration_plan(self, assistant):
        result = assistant.migration_plan(
            SAMPLE_CODE,
            source="Python 2",
            target="Python 3",
            constraints="no downtime",
        )
        assert result == "Analysis complete."

    def test_batch_review(self, assistant):
        results = assistant.batch_review({"a.py": "x=1", "b.py": "y=2"})
        assert results["a.py"] == "Analysis complete."
        assert results["b.py"] == "Analysis complete."

    def test_generate(self, assistant):
        result = assistant.generate("REST endpoint for users", language="python")
        assert result == "Analysis complete."

    def test_fix_lint(self, assistant):
        result = assistant.fix_lint(SAMPLE_CODE, "E501 line too long")
        assert result == "Analysis complete."

    def test_audit_deps(self, assistant):
        result = assistant.audit_deps("requests==2.28.0\nflask==2.0.0")
        assert result == "Analysis complete."

    def test_dependency_upgrade(self, assistant):
        result = assistant.dependency_upgrade("requests==2.28.0", constraints="no major bumps")
        assert result == "Analysis complete."

    def test_incident_triage(self, assistant):
        result = assistant.incident_triage("500 errors", logs="timeout in logs")
        assert result == "Analysis complete."

    def test_summarize_changes(self, assistant):
        result = assistant.summarize_changes("diff content", audience="reviewers")
        assert result == "Analysis complete."

    def test_generate_and_verify_success(self):
        code_response = "def add(a, b):\n    return a + b"
        client = MockLLMClient(default_response=code_response)
        assistant = CodeAssistant(client=client)
        result = assistant.generate_and_verify(
            "add function",
            "assert add(1, 2) == 3",
        )
        assert result["success"]
        assert "add" in result["code"]

    def test_architecture(self, assistant):
        result = assistant.architecture(SAMPLE_CODE, context="microservice")
        assert result == "Analysis complete."

    def test_structured_review(self):
        json_response = (
            '{"summary": "Good code", "score": 9, '
            '"issues": [{"severity": "low", "line": 1, '
            '"message": "Consider type hints", "suggestion": "Add hints"}]}'
        )
        client = MockLLMClient(default_response=json_response)
        assistant = CodeAssistant(client=client)
        result = assistant.structured_review(SAMPLE_CODE)
        assert result.score == 9
        assert result.summary == "Good code"
        assert len(result.issues) == 1

    def test_structured_security(self):
        json_response = (
            '{"summary": "No critical issues", "risk_level": "low", '
            '"findings": [{"severity": "low", "category": "auth", '
            '"description": "Missing rate limiting", "remediation": "Add rate limiter"}]}'
        )
        client = MockLLMClient(default_response=json_response)
        assistant = CodeAssistant(client=client)
        result = assistant.structured_security(SAMPLE_CODE)
        assert result.risk_level == "low"
        assert len(result.findings) == 1

    def test_structured_performance(self):
        json_response = (
            '{"summary": "Acceptable performance", "issues": '
            '[{"area": "memory", "impact": "low", '
            '"description": "Minor allocation", "fix": null}]}'
        )
        client = MockLLMClient(default_response=json_response)
        assistant = CodeAssistant(client=client)
        result = assistant.structured_performance(SAMPLE_CODE)
        assert result.summary == "Acceptable performance"
        assert len(result.issues) == 1

    @pytest.mark.asyncio
    async def test_astructured_review(self):
        json_response = '{"summary": "ok", "score": 7, "issues": []}'
        client = MockLLMClient(default_response=json_response)
        assistant = CodeAssistant(client=client)
        result = await assistant.astructured_review(SAMPLE_CODE)
        assert result.score == 7
