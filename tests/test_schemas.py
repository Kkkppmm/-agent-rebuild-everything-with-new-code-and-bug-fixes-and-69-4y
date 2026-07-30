"""Tests for DevAI structured output schemas."""

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
            issues=[
                CodeIssue(severity="low", message="Missing docstring", suggestion="Add one"),
            ],
        )
        assert result.score == 8
        assert len(result.issues) == 1
        assert result.issues[0].severity == "low"

    def test_security_audit_result(self):
        result = SecurityAuditResult(
            summary="One critical issue",
            risk_level="high",
            findings=[
                SecurityFinding(
                    severity="critical",
                    category="injection",
                    description="SQL injection risk",
                    remediation="Use parameterized queries",
                ),
            ],
        )
        assert result.risk_level == "high"
        assert result.findings[0].category == "injection"

    def test_perf_review_result(self):
        result = PerfReviewResult(
            summary="Minor issues",
            issues=[
                PerfIssue(
                    area="algorithm",
                    impact="medium",
                    description="O(n^2) loop",
                    fix="Use a hash map",
                ),
            ],
        )
        assert len(result.issues) == 1
        assert result.issues[0].area == "algorithm"

    def test_code_review_score_bounds(self):
        result = CodeReviewResult(summary="ok", score=1)
        assert result.score == 1
        result = CodeReviewResult(summary="great", score=10)
        assert result.score == 10
