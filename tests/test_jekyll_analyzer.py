"""Tests for JekyllAnalyzer."""

from pathlib import Path

from devai.jekyll_analyzer import JekyllAnalyzer, JekyllFinding


INSECURE_JEKYLL = """\
title: Demo Docs
url: http://insecure.example.com
baseurl: ""
theme: minima
api_key: sk-live-hardcoded-secret
safe: false
host: 0.0.0.0
livereload: true
highlighter: null

plugins:
  - jekyll-feed
  - jekyll-shell
  - jekyll-exec

remote_theme: https://github.com/evil/jekyll-theme
gems:
  - https://github.com/evil/gem

head_scripts:
  - https://cdn.example.com/jquery.min.js
footer_scripts:
  - https://cdn.example.com/analytics.js
"""

HARDENED_JEKYLL = """\
title: Demo Docs
url: https://example.com
baseurl: ""
theme: minima
safe: true
host: 127.0.0.1
highlighter: rouge

plugins:
  - jekyll-feed
  - jekyll-seo-tag

head_scripts: []
footer_scripts: []
"""


class TestJekyllAnalyzer:
    def test_detects_insecure_jekyll_config(self, tmp_path: Path):
        (tmp_path / "_config.yml").write_text(INSECURE_JEKYLL, encoding="utf-8")
        analyzer = JekyllAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "unsafe_safe_mode" in kinds
        assert "bind_all_interfaces" in kinds
        assert "dangerous_plugin" in kinds
        assert "remote_script" in kinds
        assert "hardcoded_secret" in kinds
        assert "remote_theme" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_jekyll_scores_well(self, tmp_path: Path):
        (tmp_path / "_config.yml").write_text(HARDENED_JEKYLL, encoding="utf-8")
        analyzer = JekyllAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_config_files_discovery(self, tmp_path: Path):
        (tmp_path / "_config.yaml").write_text(HARDENED_JEKYLL, encoding="utf-8")
        analyzer = JekyllAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "_config.yml").write_text(INSECURE_JEKYLL, encoding="utf-8")
        analyzer = JekyllAnalyzer(str(tmp_path))
        assert "Jekyll configs:" in analyzer.summary()
        assert "Jekyll analysis:" in analyzer.to_context()

    def test_generate_hardened_template(self):
        template = JekyllAnalyzer(".").generate_hardened_template()
        assert "safe: true" in template
        assert "127.0.0.1" in template

    def test_finding_format(self):
        finding = JekyllFinding(
            kind="test",
            severity="high",
            message="test message",
            path="_config.yml",
            lineno=1,
        )
        assert "[high]" in finding.format()

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = JekyllAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()
