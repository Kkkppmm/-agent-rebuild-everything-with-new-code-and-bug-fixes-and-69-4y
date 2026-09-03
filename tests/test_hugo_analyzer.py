"""Tests for HugoAnalyzer."""

from pathlib import Path

from devai.hugo_analyzer import HugoAnalyzer, HugoFinding


INSECURE_CONFIG = """\
baseURL = "http://insecure.example.com/"
languageCode = "en-us"
title = "Demo Docs"
theme = "docsy"
api_key = "sk-live-secret-token-12345"

enableRobotsTXT = false
buildDrafts = true

[markup.goldmark.renderer]
  unsafe = true
  allowActionJavaScript = true

[server]
  bind = "0.0.0.0"

[module]
  [[module.imports]]
    path = "http://evil.example.com/theme"

[params]
  customHead = '<script src="https://cdn.example.com/track.js"></script>'
"""

HARDENED_CONFIG = """\
baseURL = "https://example.com/"
languageCode = "en-us"
title = "Demo Docs"
theme = "docsy"

enableRobotsTXT = true

[markup.goldmark.renderer]
  unsafe = false

[server]
  bind = "127.0.0.1"

[params]
  description = "Documentation"
"""


class TestHugoAnalyzer:
    def test_detects_insecure_hugo_toml(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "goldmark_unsafe" in kinds
        assert "bind_all_interfaces" in kinds
        assert "insecure_http" in kinds
        assert "insecure_module" in kinds
        assert "build_drafts" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_config_toml_also_scanned(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text(
            "baseURL = 'https://example.com/'\ntitle = 'x'\nbuildDrafts = true\n",
            encoding="utf-8",
        )
        analyzer = HugoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "build_drafts" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = HugoAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_ignores_non_hugo_config(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text("DEBUG = true\nDATABASE_URL = 'sqlite:///db'\n", encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = HugoAnalyzer(".").generate_hardened_template()
        assert "unsafe = false" in template
        assert 'bind = "127.0.0.1"' in template

    def test_finding_format(self):
        finding = HugoFinding(
            kind="goldmark_unsafe",
            severity="high",
            message="test message",
            path="hugo.toml",
            lineno=2,
        )
        assert "high" in finding.format()
        assert "hugo.toml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(
            "baseURL = 'https://example.com/'\ntitle = 'x'\nbuildDrafts = true\n",
            encoding="utf-8",
        )
        analyzer = HugoAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Hugo analysis:" in context
        assert "buildDrafts" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(
            "baseURL = 'https://example.com/'\ntitle = 'x'\nbuildDrafts = true\n",
            encoding="utf-8",
        )
        analyzer = HugoAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Hugo configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "hugo.toml").write_text(
            "baseURL = 'http://evil.example.com/'\ntitle = 'x'\n[markup.goldmark.renderer]\nunsafe = true\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        hugo = next(c for c in report.categories if c.name == "hugo")
        assert hugo.score < 100.0
        assert hugo.details.get("findings", 0) > 0
