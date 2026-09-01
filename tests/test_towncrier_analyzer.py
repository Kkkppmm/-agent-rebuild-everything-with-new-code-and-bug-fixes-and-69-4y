"""Tests for TowncrierAnalyzer."""

from pathlib import Path

from devai.towncrier_analyzer import TowncrierAnalyzer, TowncrierFinding


GOOD_CONFIG = """\
[tool.towncrier]
package = "my_package"
directory = "changelog.d"
filename = "CHANGELOG.md"
title_format = "## [{version}] - {project_date}"
issue_format = "[#{issue}](https://github.com/org/repo/issues/{issue})"
create_if_missing = true
"""

INSECURE_CONFIG = """\
[tool.towncrier]
package = "my_package"
directory = "../outside/changelog.d"
filename = "CHANGELOG.md"
api_key = "sk-live-hardcoded-secret-token-12345"
issue_link = "http://insecure.example.com/issues/{issue}"
template = "fragment {{ eval('1') }}"
"""


class TestTowncrierAnalyzer:
    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_clean_config(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(GOOD_CONFIG, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        assert analyzer.stats.config_files == 1
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = TowncrierAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "path_traversal" in kinds
        assert "unsafe_template" in kinds
        assert any(f.severity == "high" for f in findings)

    def test_towncrier_toml_config(self, tmp_path: Path):
        (tmp_path / "towncrier.toml").write_text(
            '[towncrier]\npackage = "demo"\n',
            encoding="utf-8",
        )
        analyzer = TowncrierAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_CONFIG, encoding="utf-8")
        finding = TowncrierAnalyzer(str(tmp_path)).analyze()[0]
        assert isinstance(finding, TowncrierFinding)
        assert "[" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(GOOD_CONFIG, encoding="utf-8")
        ctx = TowncrierAnalyzer(str(tmp_path)).to_context()
        assert "Towncrier" in ctx
        assert "health score" in ctx

    def test_generate_template(self, tmp_path: Path):
        template = TowncrierAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "towncrier" in template.lower()
