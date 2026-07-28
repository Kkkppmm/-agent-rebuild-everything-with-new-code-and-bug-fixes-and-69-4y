"""Tests for DevAI CI reporting."""

import json

from devai.ci import (
    report_from_performance,
    report_from_program,
    report_from_review,
    report_from_security,
)
from devai.program import ProgramResult
from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)


class TestCIReports:
    def test_report_from_review_passed(self):
        result = CodeReviewResult(
            summary="Looks good",
            score=8,
            issues=[
                CodeIssue(
                    severity="low",
                    line=1,
                    message="Minor style issue",
                    suggestion="Use snake_case",
                )
            ],
        )
        report = report_from_review(result, fail_below=5)
        assert report.passed is True
        assert "8/10" in report.body
        assert "✅ Passed" in report.to_github_comment()

    def test_report_from_review_failed(self):
        result = CodeReviewResult(summary="Needs work", score=3, issues=[])
        report = report_from_review(result, fail_below=5)
        assert report.passed is False
        assert "❌ Failed" in report.to_github_comment()

    def test_report_from_review_annotations(self):
        result = CodeReviewResult(
            summary="Critical issues",
            score=2,
            issues=[
                CodeIssue(
                    severity="critical",
                    line=42,
                    message="SQL injection risk",
                    suggestion=None,
                )
            ],
        )
        report = report_from_review(result)
        assert len(report.annotations) == 1
        assert report.annotations[0]["start_line"] == 42

    def test_report_from_security(self):
        result = SecurityAuditResult(
            summary="One finding",
            risk_level="high",
            findings=[
                SecurityFinding(
                    severity="high",
                    category="injection",
                    description="Unsanitized input",
                    remediation="Use parameterized queries",
                )
            ],
        )
        report = report_from_security(result)
        assert report.passed is False
        assert "injection" in report.body

    def test_report_from_performance(self):
        result = PerfReviewResult(
            summary="Performance concerns",
            issues=[
                PerfIssue(
                    area="database",
                    impact="high",
                    description="N+1 query",
                    fix="Use eager loading",
                )
            ],
        )
        report = report_from_performance(result)
        assert report.passed is False
        assert "N+1 query" in report.body

    def test_report_from_program(self):
        results = [
            ProgramResult(name="review", action="review", output="All good."),
        ]
        report = report_from_program(results)
        assert report.passed is True
        assert "review" in report.body

    def test_report_to_json(self):
        result = CodeReviewResult(summary="OK", score=7, issues=[])
        report = report_from_review(result)
        data = json.loads(report.to_json())
        assert data["passed"] is True
        assert data["title"] == "DevAI Code Review"
