"""Tests for CodeComparer."""

from pathlib import Path

from devai import CodeComparer, CompareResult, DevAI


class TestCompareResult:
    def test_has_changes_true(self):
        result = CompareResult("a", "b", "diff", 1, 1, 2)
        assert result.has_changes is True

    def test_has_changes_false(self):
        result = CompareResult("a", "b", "", 0, 0, 0)
        assert result.has_changes is False


class TestCodeComparer:
    def test_compare_strings(self):
        ai = DevAI.mock()
        comparer = CodeComparer(ai.assistant)
        result = comparer.compare("x = 1", "x = 2")
        assert isinstance(result, CompareResult)
        assert result.has_changes
        assert "-x = 1" in result.diff or "x = 1" in result.diff
        assert result.additions >= 1

    def test_compare_identical(self):
        ai = DevAI.mock()
        comparer = CodeComparer(ai.assistant)
        result = comparer.compare("same", "same")
        assert not result.has_changes

    def test_compare_files(self, tmp_path: Path):
        before = tmp_path / "before.py"
        after = tmp_path / "after.py"
        before.write_text("def foo():\n    return 1\n")
        after.write_text("def foo():\n    return 2\n")

        ai = DevAI.mock()
        comparer = CodeComparer(ai.assistant)
        result = comparer.compare_files(before, after)
        assert result.has_changes
        assert "before.py" in result.before_label or "before.py" in result.diff

    def test_review_changes(self):
        ai = DevAI.mock()
        comparer = CodeComparer(ai.assistant)
        review = comparer.review_changes("a = 1", "a = 2")
        assert isinstance(review, str)
        assert review

    def test_review_no_changes(self):
        ai = DevAI.mock()
        comparer = CodeComparer(ai.assistant)
        assert comparer.review_changes("same", "same") == "No changes detected."

    def test_summarize_changes(self):
        ai = DevAI.mock()
        comparer = CodeComparer(ai.assistant)
        summary = comparer.summarize_changes("old", "new")
        assert isinstance(summary, str)
        assert summary

    def test_facade_compare(self):
        ai = DevAI.mock()
        result = ai.compare("a = 1", "a = 2")
        assert isinstance(result, CompareResult)

    def test_facade_compare_review(self):
        ai = DevAI.mock()
        review = ai.compare("a = 1", "a = 2", review=True)
        assert isinstance(review, str)
