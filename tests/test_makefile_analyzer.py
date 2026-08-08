"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer


GOOD_MAKEFILE = """\
.PHONY: help install test clean

help:
\t@echo "Targets: install test clean"

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

clean:
\tfind . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
"""


class TestMakefileAnalyzer:
    def test_no_makefile_returns_empty(self, tmp_path: Path):
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary().lower()

    def test_clean_makefile(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(GOOD_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        stats = analyzer.stats
        assert stats.makefiles == 1
        assert stats.targets >= 4
        assert analyzer.health_score() >= 90.0

    def test_detects_curl_pipe_shell(self, tmp_path: Path):
        makefile = (
            "install:\n"
            "\tcurl https://example.com/install.sh | bash\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "curl_pipe_shell" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_eval(self, tmp_path: Path):
        makefile = "run:\n\teval $(cat script.sh)\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "eval_usage" for f in findings)

    def test_detects_secret(self, tmp_path: Path):
        makefile = "deploy:\n\texport API_KEY='sk_live_abc123secret'\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_makefile" for f in findings)

    def test_detects_sudo(self, tmp_path: Path):
        makefile = "install:\n\tsudo apt-get install build-essential\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "sudo_usage" for f in findings)

    def test_detects_chmod_777(self, tmp_path: Path):
        makefile = "setup:\n\tchmod 777 ./run.sh\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "chmod_777" for f in findings)

    def test_detects_force_push(self, tmp_path: Path):
        makefile = "release:\n\tgit push origin main --force\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "force_push" for f in findings)

    def test_generate_template(self, tmp_path: Path):
        analyzer = MakefileAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert ".PHONY" in template
        assert "pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(GOOD_MAKEFILE, encoding="utf-8")
        context = MakefileAnalyzer(str(tmp_path)).to_context()
        assert "Makefile analysis" in context
        assert "health score" in context

    def test_finds_gnumakefile(self, tmp_path: Path):
        (tmp_path / "GNUmakefile").write_text("all:\n\t@echo ok\n", encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        assert len(analyzer.makefiles()) == 1
