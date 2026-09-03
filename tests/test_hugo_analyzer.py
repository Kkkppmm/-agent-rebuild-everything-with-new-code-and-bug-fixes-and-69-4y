"""Tests for HugoAnalyzer."""

from pathlib import Path

from devai.hugo_analyzer import HugoAnalyzer, HugoFinding


INSECURE_HUGO = """\
baseURL = "http://insecure.example.com/"
title = "Demo Docs"
theme = "docsy"

enableRobotsTXT = false
enableGitInfo = true
ignoreErrors = true

[markup.goldmark.renderer]
  unsafe = true

[server]
  bind = "0.0.0.0"
  port = 1313

publishDir = "../outside/public"

[module]
  [[module.imports]]
    path = "https://user:secretpass@github.com/org/theme"
"""

HARDENED_HUGO = """\
baseURL = "https://example.com/"
title = "Demo Docs"
theme = "docsy"

enableRobotsTXT = true
enableGitInfo = false

[markup.goldmark.renderer]
  unsafe = false

[server]
  bind = "127.0.0.1"
  port = 1313

publishDir = "public"
"""


class TestHugoAnalyzer:
    def test_detects_insecure_hugo_toml(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(INSECURE_HUGO, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "goldmark_unsafe" in kinds
        assert "server_bind_all" in kinds
        assert "publish_dir_outside" in kinds
        assert "module_credentials" in kinds
        assert "ignore_errors" in kinds
        assert "robots_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_hugo_scores_well(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text(HARDENED_HUGO, encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_config_toml_also_scanned(self, tmp_path: Path):
        (tmp_path / "config.toml").write_text(
            'baseURL = "http://insecure.example.com/"\n',
            encoding="utf-8",
        )
        analyzer = HugoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "insecure_http" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = HugoAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = HugoAnalyzer(".").generate_hardened_template()
        assert "unsafe = false" in template
        assert "127.0.0.1" in template

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
        (tmp_path / "hugo.toml").write_text('[markup.goldmark.renderer]\n  unsafe = true\n', encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Hugo analysis:" in context
        assert "Goldmark" in context or "goldmark" in context.lower()

    def test_summary(self, tmp_path: Path):
        (tmp_path / "hugo.toml").write_text('[markup.goldmark.renderer]\n  unsafe = true\n', encoding="utf-8")
        analyzer = HugoAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Hugo configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "hugo.toml").write_text(
            '[markup.goldmark.renderer]\n  unsafe = true\nbind = "0.0.0.0"\n',
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        hugo = next(c for c in report.categories if c.name == "hugo")
        assert hugo.score < 100.0
        assert hugo.details.get("findings", 0) > 0
