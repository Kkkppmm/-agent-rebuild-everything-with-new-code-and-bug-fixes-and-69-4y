"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding


INSECURE_MAKEFILE = """
.PHONY: install

install:
\tcurl -fsSL https://example.com/install.sh | bash
\tAPI_KEY=sk-hardcoded-secret pip install .

clean:
\tsudo rm -rf /
\trm -rf build/*
"""

HARDENED_MAKEFILE = """
.PHONY: install test clean

install:
\tpip install -e ".[dev]"

test:
\tpytest

clean:
\trm -rf build dist *.egg-info
"""


class TestMakefileAnalyzer:
    def test_no_makefile_returns_perfect_score(self, tmp_path: Path):
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert analyzer.stats.makefiles == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(INSECURE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_secret" in kinds
        assert "sudo_usage" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_makefile_scores_well(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert "Makefiles:" in analyzer.summary()
        assert "Makefile analysis" in analyzer.to_context()

    def test_finding_format(self):
        finding = MakefileFinding(
            kind="sudo_usage",
            severity="medium",
            message="uses sudo",
            path="Makefile",
            lineno=5,
            target="clean",
        )
        assert "Makefile:5" in finding.format()
        assert "clean" in finding.format()
