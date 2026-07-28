"""Tests for CI report helpers."""

from devai import (
    CodeIssue,
    CodeReviewResult,
    PerfIssue,
    PerfReviewResult,
    SecurityAuditResult,
    SecurityFinding,
    merge_reports,
    report_from_performance_review,
    report_from_program_results,
    report_from_security_audit,
    report_from_structured_review,
)
from devai.ci import CIAnnotation, CIReport
from devai.program import ProgramResult


class TestCIAnnotation:
    def test_github_actions_basic(self):
        ann = CIAnnotation(level="error", message="bad code")
        assert ann.to_github_actions() == "::error::bad code"

    def test_github_actions_with_location(self):
        ann = CIAnnotation(
            level="warning",
            message="line too long",
            file="app.py",
            line=10,
            col=5,
            title="Lint",
        )
        result = ann.to_github_actions()
        assert result.startswith("::warning file=app.py,line=10,col=5,title=Lint::")


class TestCIReport:
    def test_github_comment_passed(self):
        report = CIReport(title="Test")
        report.add_section("Review", "All good")
        comment = report.to_github_comment()
        assert "✅ Passed" in comment
        assert "### Review" in comment

    def test_github_comment_failed(self):
        report = CIReport()
        report.add_annotation("critical bug", level="error")
        comment = report.to_github_comment()
        assert "❌ Failed" in comment

    def test_write_annotations(self):
        report = CIReport()
        report.add_annotation("issue", level="warning", file="x.py", line=1)
        lines = report.to_github_actions_annotations()
        assert len(lines) == 1
        assert "warning" in lines[0]


class TestReportBuilders:
    def test_from_program_results(self):
        results = [
            ProgramResult(name="review", action="review", output="Looks fine"),
            ProgramResult(name="security", action="security", output="No issues"),
        ]
        report = report_from_program_results(results)
        assert report.passed
        assert len(report.sections) == 2

    def test_from_program_security_failure(self):
        results = [
            ProgramResult(
                name="security",
                action="security",
                output="Critical vulnerability found",
            ),
        ]
        report = report_from_program_results(results)
        assert not report.passed

    def test_from_structured_review(self):
        review = CodeReviewResult(
            summary="Decent code",
            score=8,
            issues=[
                CodeIssue(severity="low", message="minor style", line=3),
            ],
        )
        report = report_from_structured_review(review, file="app.py", min_score=7)
        assert report.passed
        assert report.metadata["score"] == 8

    def test_from_structured_review_fails_score(self):
        review = CodeReviewResult(summary="Needs work", score=4)
        report = report_from_structured_review(review, min_score=7)
        assert not report.passed

    def test_from_security_audit(self):
        audit = SecurityAuditResult(
            summary="Some risks",
            risk_level="high",
            findings=[
                SecurityFinding(
                    severity="high",
                    category="auth",
                    description="Missing auth check",
                ),
            ],
        )
        report = report_from_security_audit(audit, max_risk="medium")
        assert not report.passed

    def test_from_performance_review(self):
        perf = PerfReviewResult(
            summary="OK",
            issues=[
                PerfIssue(area="algorithm", impact="medium", description="O(n^2) loop"),
            ],
        )
        report = report_from_performance_review(perf)
        assert report.passed
        assert len(report.annotations) == 1

    def test_merge_reports(self):
        r1 = CIReport(title="A", passed=True)
        r1.add_section("Step 1", "ok")
        r2 = CIReport(title="B", passed=False)
        r2.add_annotation("fail", level="error")
        merged = merge_reports(r1, r2, title="Combined")
        assert merged.title == "Combined"
        assert not merged.passed
        assert len(merged.sections) == 1
        assert len(merged.annotations) == 1
