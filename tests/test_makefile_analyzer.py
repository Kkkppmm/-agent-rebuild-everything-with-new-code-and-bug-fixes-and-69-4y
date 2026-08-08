"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding


INSECURE_MAKEFILE = """
API_KEY=supersecret1234
all:
\tcurl -fsSL https://example.com/install.sh | bash
\tsudo apt-get install -y build-essential
\tchmod 777 /tmp/app
\teval $(curl -s https://example.com/script.sh)
\tdocker run --privileged ubuntu:latest
\trm -rf /
\tgit clone https://github.com/example/repo.git main

clean:
\trm -f *.o
"""

HARDENED_MAKEFILE = """
.PHONY: all test clean install

PYTHON ?= python3

all: test

install:
\t$(PYTHON) -m pip install -e ".[dev]"

test:
\t$(PYTHON) -m pytest

clean:
\trm -f *.o *.pyc
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
        assert "secret_in_var" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_usage" in kinds
        assert "chmod_777" in kinds
        assert "eval_usage" in kinds
        assert "privileged_docker" in kinds
        assert "dangerous_rm" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_makefile_scores_well(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.makefiles == 1
        assert analyzer.infos[0].has_phony is True

    def test_finds_nested_makefiles(self, tmp_path: Path):
        build = tmp_path / "build"
        build.mkdir()
        (build / "rules.mk").write_text("all:\n\techo ok\n", encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert analyzer.stats.makefiles == 1

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(HARDENED_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert "Makefiles:" in analyzer.summary()
        assert "Makefile analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert ".PHONY:" in template
        assert "pytest" in template

    def test_finding_format(self):
        finding = MakefileFinding(
            kind="sudo_usage",
            severity="medium",
            message="uses sudo",
            path="Makefile",
            lineno=3,
        )
        assert "Makefile:3" in finding.format()
        assert "medium" in finding.format()
