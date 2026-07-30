"""Tests for batch code review."""

from pathlib import Path

import pytest

from devai import CodeAssistant, MockLLMClient
from devai.batch_review import BatchReviewer, BatchReviewReport, FileReviewResult


def _assistant() -> CodeAssistant:
    return CodeAssistant(client=MockLLMClient())


class TestFileReviewResult:
    def test_ok_property(self):
        ok = FileReviewResult(path="a.py", review="looks good")
        bad = FileReviewResult(path="b.py", review="", error="missing")
        assert ok.ok is True
        assert bad.ok is False


class TestBatchReviewReport:
    def test_summary_and_markdown(self):
        report = BatchReviewReport(
            results=[
                FileReviewResult(path="a.py", review="review a", language="python"),
                FileReviewResult(path="b.py", review="", error="not found"),
            ]
        )
        assert "1 file(s)" in report.summary()
        assert len(report.reviewed) == 1
        assert len(report.failed) == 1
        md = report.to_markdown()
        assert "# Batch Code Review" in md
        assert "a.py" in md
        assert "not found" in md


class TestBatchReviewer:
    def test_review_file(self, tmp_path: Path):
        src = tmp_path / "sample.py"
        src.write_text("def hello():\n    pass\n", encoding="utf-8")
        reviewer = BatchReviewer(_assistant())
        result = reviewer.review_file(src)
        assert result.ok
        assert result.language == "python"
        assert result.review

    def test_review_missing_file(self):
        reviewer = BatchReviewer(_assistant())
        result = reviewer.review_file("/nonexistent/file.py")
        assert not result.ok
        assert "not found" in (result.error or "").lower()

    def test_review_files(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
        reviewer = BatchReviewer(_assistant(), max_workers=2)
        report = reviewer.review_files([tmp_path / "a.py", tmp_path / "b.py"])
        assert len(report.results) == 2
        assert all(r.ok for r in report.results)

    def test_review_directory(self, tmp_path: Path):
        (tmp_path / "one.py").write_text("a = 1\n", encoding="utf-8")
        sub = tmp_path / "pkg"
        sub.mkdir()
        (sub / "two.py").write_text("b = 2\n", encoding="utf-8")
        reviewer = BatchReviewer(_assistant())
        report = reviewer.review_directory(tmp_path, pattern="*.py", recursive=True)
        assert len(report.reviewed) == 2

    def test_review_empty_directory(self, tmp_path: Path):
        reviewer = BatchReviewer(_assistant())
        report = reviewer.review_directory(tmp_path, pattern="*.py")
        assert len(report.failed) == 1

    @pytest.mark.asyncio
    async def test_areview_files(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
        reviewer = BatchReviewer(_assistant())
        report = await reviewer.areview_files([tmp_path / "a.py", tmp_path / "b.py"])
        assert len(report.results) == 2
        assert all(r.ok for r in report.results)

    @pytest.mark.asyncio
    async def test_areview_directory(self, tmp_path: Path):
        (tmp_path / "mod.py").write_text("z = 3\n", encoding="utf-8")
        reviewer = BatchReviewer(_assistant())
        report = await reviewer.areview_directory(tmp_path, pattern="*.py")
        assert len(report.reviewed) == 1
