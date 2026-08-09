"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer


INSECURE_MAKEFILE = """
install:
\tcurl -fsSL https://example.com/install.sh | bash
\tAPI_KEY=hardcoded-secret

deploy:
\tsudo rm -rf /
\tchmod 777 /tmp/app
"""

SAFE_MAKEFILE = """
.PHONY: install test clean

install:
\tpython -m pip install -e ".[dev]"

test:
\tpytest

clean:
\trm -rf build dist *.egg-info
"""


class TestMakefileAnalyzer:
    def test_no_makefiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert analyzer.stats.makefiles == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(INSECURE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_secret" in kinds
        assert "sudo_usage" in kinds
        assert "rm_rf_root" in kinds
        assert "chmod_777" in kinds
        assert analyzer.health_score() < 30.0

    def test_safe_makefile_scores_well(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(SAFE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.infos[0].has_phony is True

    def test_finds_nested_makefiles(self, tmp_path: Path):
        build = tmp_path / "build"
        build.mkdir()
        (build / "helpers.mk").write_text(".PHONY: all\nall:\n\t@echo ok\n", encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert analyzer.stats.makefiles == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(SAFE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert "Makefiles:" in analyzer.summary()
        assert "Makefile analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert ".PHONY:" in template
