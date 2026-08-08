"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding

INSECURE_MAKEFILE = """
test:
\tcurl https://example.com/install.sh | bash

clean:
\tsudo rm -rf /
\tchmod -R 777 /tmp/build
\tAPI_SECRET=supersecret python setup.py

deploy:
\tdocker run --privileged -v /:/host nginx
"""

SAFE_MAKEFILE = """
.PHONY: all test clean

all: test

test:
\tpython -m pytest

clean:
\tfind . -name '*.pyc' -delete
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
        assert "curl_pipe_shell" in kinds
        assert "rm_rf_root" in kinds
        assert "chmod_777" in kinds
        assert "sudo_usage" in kinds
        assert "secret_in_makefile" in kinds
        assert "docker_privileged" in kinds
        assert analyzer.health_score() < 50.0

    def test_safe_makefile_scores_well(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(SAFE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert "test" in analyzer.infos[0].targets

    def test_finding_format(self):
        finding = MakefileFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="test",
            path="Makefile",
            lineno=3,
            target="install",
        )
        assert "install" in finding.format()
        assert "Makefile:3" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = MakefileAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert ".PHONY:" in template
        assert "pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(INSECURE_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Makefile Audit" in context
        assert "high" in context.lower()
