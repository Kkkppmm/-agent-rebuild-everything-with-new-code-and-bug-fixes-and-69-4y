"""Tests for HugoAnalyzer."""

from pathlib import Path

from devai.hugo_analyzer import HugoAnalyzer, HugoFinding


INSECURE_HUGO = """\
baseURL = "http://insecure.example.com/"
title = "Demo Docs"
theme = "docsy"
api_key = "sk-live-hardcoded-secret"

[markup.goldmark.renderer]
  unsafe = true

[server]
  bindAddress = "0.0.0.0"

[params]
  googleAnalytics = "UA-123456-1"

customJS = ["https://cdn.example.com/jquery.min.js"]
customCSS = ["https://cdn.example.com/theme.css"]

ignoreErrors = true

[module]
  [[module.imports]]
    path = "https://github.com/evil/module"
"""

HARDENED_HUGO = """\
baseURL = "https://example.com/"
title = "Demo Docs"
theme = "docsy"

[markup.goldmark.renderer]
  unsafe = false

[server]
  bind = "127.0.0.1"

customJS = []
customCSS = []
"""


class TestHugoAnalyzer:
    def test_detects_insecure_hugo_toml(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(INSECURE_HUGO, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "unsafe_markup" in kinds
        assert "bind_all_interfaces" in kinds
        assert "remote_script" in kinds
        assert "hardcoded_secret" in kinds
        assert "external_module" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_hugo_scores_well(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(HARDENED_HUGO, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text(HARDENED_HUGO, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(INSECURE_HUGO, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        assert "Hugo configs:" in analyzer.summary()
        assert "Hugo analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = HugoAnalyzer(".").generate_hardened_template()
        assert "unsafe = false" in template
        assert "127.0.0.1" in template

    def test_finding_format(self):
        finding = HugoFinding(
            kind="test",
            severity="high",
            message="test message",
            path="hugo.toml",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = HugoAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
