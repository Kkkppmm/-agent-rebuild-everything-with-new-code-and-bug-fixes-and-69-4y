"""Tests for quickstart helpers."""

from devai.quickstart import assistant, quickstart


class TestQuickstart:
    def test_quickstart_mock(self):
        runtime = quickstart(use_mock=True)
        result = runtime.review("def foo(): pass")
        assert isinstance(result, str)

    def test_assistant_mock(self):
        asst = assistant(use_mock=True)
        result = asst.explain("x = 1")
        assert isinstance(result, str)
