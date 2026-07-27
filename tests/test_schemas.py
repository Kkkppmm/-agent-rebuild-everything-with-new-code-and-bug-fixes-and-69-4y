"""Tests for DevAI schemas."""

from devai.schemas import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
)


class TestSchemas:
    def test_code_review_result(self):
        result = CodeReviewResult(
            summary="Looks good",
            score=8,
            issues=[CodeIssue(severity="low", message="Missing docstring")],
        )
        assert result.score == 8
        assert len(result.issues) == 1

    def test_security_audit_result(self):
        result = SecurityAuditResult(
            summary="One issue found",
            risk_level="medium",
            findings=[
                SecurityFinding(
                    severity="medium",
                    category="secrets",
                    description="Hardcoded API key",
                )
            ],
        )
        assert result.risk_level == "medium"

    def test_perf_review_result(self):
        result = PerfReviewResult(
            summary="Minor issues",
            issues=[PerfIssue(area="algorithm", impact="low", description="O(n^2) loop")],
        )
        assert len(result.issues) == 1
