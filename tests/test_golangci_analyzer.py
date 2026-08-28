"""Tests for GolangciLintAnalyzer."""

from pathlib import Path

from devai.golangci_analyzer import GolangciLintAnalyzer, GolangciFinding


INSECURE_CONFIG = """\
run:
  timeout: 45m
  skip-dirs:
    - src
    - internal
  skip-files:
    - .*
  build-tags:
    - debug
    - unsafe
  allow-parallel-runners: true
  modules-download-mode: mod
  api_key: hardcoded_secret_value_12345

linters:
  disable-all: true
  disable:
    - gosec
    - bodyclose
  enable:
    - errcheck

issues:
  exclude-use-default: true
  exclude-rules:
    - text: "*"
      linters:
        - gosec

linters-settings:
  gosec:
    excludes:
      - G104
      - G401
"""

HARDENED_CONFIG = """\
run:
  timeout: 5m
  tests: true
  modules-download-mode: readonly

linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - gosec
    - bodyclose
    - noctx

issues:
  exclude-use-default: false
  max-issues-per-linter: 0
"""


class TestGolangciLintAnalyzer:
    def test_detects_insecure_config(self, tmp_path: Path):
        (tmp_path / ".golangci.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = GolangciLintAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "disable_all" in kinds
        assert "disabled_security_linter" in kinds
        assert "skip_dirs_source" in kinds
        assert "skip_files_broad" in kinds
        assert "gosec_excludes" in kinds
        assert "broad_exclude_rule" in kinds
        assert "build_tags_risky" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".golangci.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = GolangciLintAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = GolangciLintAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = GolangciFinding(
            kind="disable_all",
            severity="high",
            message="test message",
            path=".golangci.yml",
            lineno=10,
            line="  disable-all: true",
        )
        assert "[high]" in finding.format()
        assert ".golangci.yml:10" in finding.format()

    def test_generate_hardened_template(self, tmp_path: Path):
        analyzer = GolangciLintAnalyzer(str(tmp_path))
        template = analyzer.generate_hardened_template()
        assert "gosec" in template
        assert "readonly" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".golangci.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = GolangciLintAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "golangci-lint analysis:" in context
        assert "disable-all" in context or "gosec" in context

    def test_supports_yaml_and_toml_names(self, tmp_path: Path):
        (tmp_path / "golangci.toml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = GolangciLintAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1
        assert analyzer.config_files()[0].name == "golangci.toml"
