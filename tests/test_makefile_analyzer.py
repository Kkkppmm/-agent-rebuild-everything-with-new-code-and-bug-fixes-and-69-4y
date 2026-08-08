"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding


INSECURE_MAKEFILE = """
install:
\tcurl -fsSL https://example.com/install.sh | bash
\tAPI_KEY=supersecret pip install requests
\tgit push origin main --force
\tsudo rm -rf /
\tdocker run --privileged ubuntu

test:
\tchmod 777 /tmp/app.sock
"""

HARDENED_MAKEFILE = """
.PHONY: install test lint clean

install:
\tpython -m venv .venv
\t.venv/bin/pip install -e ".[dev]"

test:
\t.venv/bin/python -m pytest

clean:
\trm -rf build dist *.egg-info
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
        assert "secret_in_variable" in kinds
        assert "git_force_push" in kinds
        assert "dangerous_rm" in kinds
        assert "docker_privileged" in kinds
        assert "chmod_777" in kinds
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
        (build / "tasks.mk").write_text("all:\n\techo ok\n", encoding="utf-8")
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
            kind="curl_pipe_shell",
            severity="high",
            message="unsafe",
            path="Makefile",
            lineno=2,
            target="install",
        )
        assert "Makefile:2" in finding.format()
        assert "install" in finding.format()
