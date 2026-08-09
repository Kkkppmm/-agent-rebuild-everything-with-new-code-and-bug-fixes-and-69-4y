"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding


INSECURE_MAKEFILE = """
install:
\tcurl -fsSL https://example.com/install.sh | bash

deploy:
\tsudo rm -rf /
\tchmod 777 /tmp/app
\tAPI_SECRET=supersecret123 make build

push:
\tgit push origin main --force
"""

HARDENED_MAKEFILE = """
.PHONY: install test lint clean

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

clean:
\trm -rf build dist .pytest_cache
"""


class TestMakefileAnalyzer:
    def test_no_makefiles_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
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
        assert "destructive_rm" in kinds
        assert "chmod_777" in kinds
        assert "secret_in_var" in kinds
        assert "git_force_push" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_makefile_scores_well(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.makefiles == 1
        assert analyzer.infos[0].has_phony is True

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert "Makefiles:" in analyzer.summary()
        assert "Makefile analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert ".PHONY:" in template

    def test_finding_format(self):
        finding = MakefileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="unsafe",
            path="Makefile",
            lineno=2,
        )
        assert "Makefile:2" in finding.format()
