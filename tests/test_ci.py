"""Tests for DevAI CI report helpers."""

import json

from devai import CodeAssistant, CIReport, CIReporter
from devai.core import MockLLMClient

SAMPLE_CODE = "def add(a, b):\n    return a + b"

REVIEW_JSON = json.dumps(
    {
        "summary": "Code looks good overall.",
        "score": 8,
        "issues": [
            {
                "severity": "low",
                "line": 1,
                "message": "Missing type hints",
                "suggestion": "Add int type hints",
            }
        ],
    }
)

SECURITY_JSON = json.dumps(
    {
        "summary": "No critical vulnerabilities found.",
        "risk_level": "low",
        "findings": [],
    }
)


class TestCIReport:
    def test_to_markdown(self):
        report = CIReport(
            title="Test Report",
            summary="All checks passed.",
            sections=[{"title": "Review", "body": "Looks good."}],
            passed=True,
        )
        md = report.to_markdown()
        assert "Test Report" in md
        assert "✅ Passed" in md
        assert "Looks good." in md

    def test_to_github_comment(self):
        report = CIReport(title="CI", summary="OK", passed=True)
        comment = report.to_github_comment()
        assert "DevAI" in comment

    def test_to_actions_annotations(self):
        report = CIReport(
            title="CI",
            summary="Issues found",
            sections=[
                {
                    "title": "Error",
                    "body": "Something broke",
                    "level": "error",
                    "path": "app.py",
                    "line": 10,
                }
            ],
            passed=False,
        )
        annotations = report.to_actions_annotations()
        assert len(annotations) == 1
        assert annotations[0]["annotation_level"] == "error"
        assert annotations[0]["path"] == "app.py"

    def test_to_json(self):
        report = CIReport(title="CI", summary="OK", passed=True)
        data = json.loads(report.to_json())
        assert data["passed"] is True


class TestCIReporter:
    def test_review_diff(self):
        client = MockLLMClient(default_response="No issues found in diff.")
        reporter = CIReporter(CodeAssistant(client=client))
        report = reporter.review_diff("diff --git a/app.py")
        assert report.passed is True
        assert len(report.sections) == 1

    def test_code_review_gate(self):
        client = MockLLMClient(responses=[REVIEW_JSON])
        reporter = CIReporter(CodeAssistant(client=client))
        report = reporter.code_review_gate(SAMPLE_CODE)
        assert report.passed is True
        assert report.metadata["score"] == 8

    def test_security_gate(self):
        client = MockLLMClient(responses=[SECURITY_JSON])
        reporter = CIReporter(CodeAssistant(client=client))
        report = reporter.security_gate(SAMPLE_CODE)
        assert report.passed is True
        assert report.metadata["risk_level"] == "low"

    def test_full_ci_gate(self):
        client = MockLLMClient(responses=[REVIEW_JSON, SECURITY_JSON])
        reporter = CIReporter(CodeAssistant(client=client))
        report = reporter.full_ci_gate(SAMPLE_CODE)
        assert report.passed is True
        assert "DevAI CI Gate" in report.title
