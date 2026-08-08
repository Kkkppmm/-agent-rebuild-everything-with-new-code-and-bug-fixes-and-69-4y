"""Tests for MakefileAnalyzer."""

from pathlib import Path

from devai.makefile_analyzer import MakefileAnalyzer, MakefileFinding


GOOD_MAKEFILE = """\
.PHONY: help install test clean

help:
\t@echo "Targets: install test clean"

install:
\tpip install -e ".[dev]"

test:
\tpython -m pytest

clean:
\trm -rf build dist *.egg-info
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
        assert stats.targets == 4
        assert analyzer.health_score() == 100.0

    def test_detects_curl_pipe_shell(self, tmp_path: Path):
        makefile = (
            ".PHONY: setup\n"
            "setup:\n"
            "\tcurl https://example.com/install.sh | bash\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "curl_pipe_shell" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_detects_dangerous_rm(self, tmp_path: Path):
        makefile = (
            ".PHONY: clean\n"
            "clean:\n"
            "\trm -rf /\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "dangerous_rm" for f in findings)

    def test_detects_sudo(self, tmp_path: Path):
        makefile = (
            ".PHONY: install\n"
            "install:\n"
            "\tsudo pip install -r requirements.txt\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "sudo_usage" for f in findings)

    def test_detects_secret(self, tmp_path: Path):
        makefile = (
            ".PHONY: deploy\n"
            "deploy:\n"
            "\tAPI_KEY='sk_live_abc123secret' ./deploy.sh\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "secret_in_makefile" for f in findings)

    def test_detects_force_push(self, tmp_path: Path):
        makefile = (
            ".PHONY: release\n"
            "release:\n"
            "\tgit push origin main --force\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "force_push" for f in findings)

    def test_detects_privileged_docker(self, tmp_path: Path):
        makefile = (
            ".PHONY: run\n"
            "run:\n"
            "\tdocker run --privileged ubuntu:latest bash\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "privileged_docker" for f in findings)
        assert any(f.kind == "unpinned_docker_image" for f in findings)

    def test_detects_missing_phony(self, tmp_path: Path):
        makefile = (
            "clean:\n"
            "\trm -rf build\n"
        )
        (tmp_path / "Makefile").write_text(makefile, encoding="utf-8")
        findings = MakefileAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "missing_phony" for f in findings)

    def test_generate_hardened_template(self, tmp_path: Path):
        template = MakefileAnalyzer(str(tmp_path)).generate_hardened_template()
        assert ".PHONY:" in template
        assert "pytest" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Makefile").write_text(GOOD_MAKEFILE, encoding="utf-8")
        analyzer = MakefileAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Makefile analysis:" in context
        assert "health score" in context

    def test_finding_format(self):
        finding = MakefileFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Makefile",
            lineno=1,
            target="install",
        )
        assert "install" in finding.format()
        assert "high" in finding.format()
