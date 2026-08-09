"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding


GOOD_MAKEFILE = """\
.PHONY: test lint clean

test:
\tpython -m pytest

lint:
\truff check src tests

clean:
\tfind . -type d -name __pycache__ -exec rm -rf {} +
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
        assert not findings
        stats = analyzer.stats
        assert stats.makefiles == 1
        assert stats.targets >= 3
        assert analyzer.health_score() == 100.0

    def test_detects_curl_pipe_shell(self, tmp_path: Path):
        makefile = "install:\n\tcurl -fsSL https://example.com/install.sh | bash\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "curl_pipe_shell" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_dangerous_rm(self, tmp_path: Path):
        makefile = "clean:\n\trm -rf /\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "dangerous_rm" for f in findings)

    def test_detects_chmod_777(self, tmp_path: Path):
        makefile = "setup:\n\tchmod 777 build/\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "chmod_777" for f in findings)

    def test_detects_sudo(self, tmp_path: Path):
        makefile = "deploy:\n\tsudo systemctl restart app\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "sudo_usage" for f in findings)

    def test_detects_secret_in_makefile(self, tmp_path: Path):
        makefile = "API_KEY=sk-live-supersecretvalue\n"
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_makefile" for f in findings)

    def test_finding_format(self):
        finding = MakefileFinding(
            kind="test",
            severity="high",
            message="msg",
            path="Makefile",
            lineno=1,
            target="build",
        )
        assert "build" in finding.format()
        assert "Makefile:1" in finding.format()

    def test_generate_template(self, tmp_path: Path):
        analyzer = MakefileAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert ".PHONY" in template
        assert "pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text("bad:\n\trm -rf /\n", encoding="utf-8")
        context = MakefileAnalyzer(str(tmp_path)).to_context()
        assert "Makefile analysis" in context
        assert "dangerous_rm" in context or "rm" in context.lower()
