"""Tests for v8.23.0 documentation infrastructure analyzers."""

from pathlib import Path

from devai import DevAI, GitBookAnalyzer, ReadTheDocsAnalyzer


class TestV823Infrastructure:
    def test_gitbook_analyzer_public_api(self, tmp_path: Path):
        (tmp_path / ".gitbook.yaml").write_text(
            "variables:\n  token: leaked\n",
            encoding="utf-8",
        )
        analyzer = GitBookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_readthedocs_analyzer_public_api(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(
            "fail_on_warning: false\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(findings) >= 1
        assert analyzer.health_score() < 100.0

    def test_facade_methods(self, tmp_path: Path):
        dev = DevAI.mock()
        assert isinstance(dev.gitbook(tmp_path), GitBookAnalyzer)
        assert isinstance(dev.readthedocs(tmp_path), ReadTheDocsAnalyzer)
