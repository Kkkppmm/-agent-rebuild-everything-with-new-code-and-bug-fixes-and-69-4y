"""Tests for Flake8Analyzer."""

from pathlib import Path

from devai.flake8_analyzer import Flake8Analyzer, Flake8Finding


INSECURE_FLAKE8 = """\
[flake8]
max-line-length = 300
ignore = E,W,F
extend-ignore = S101, S608
exclude = src, lib, .git
per-file-ignores = settings.py: S101, S608
api_key = api_key=hardcoded_secret_value_12345
"""

HARDENED_FLAKE8 = """\
[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude =
    .git,
    __pycache__,
    .venv
per-file-ignores =
    tests/*: S101
"""


class TestFlake8Analyzer:
    def test_detects_insecure_flake8(self, tmp_path: Path):
        (tmp_path / ".flake8").write_text(INSECURE_FLAKE8, encoding="utf-8")
        analyzer = Flake8Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "broad_ignore" in kinds or "ignore_all" in kinds
        assert "disabled_security_rules" in kinds
        assert "exclude_source" in kinds
        assert "per_file_security_ignore" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_flake8_scores_well(self, tmp_path: Path):
        (tmp_path / ".flake8").write_text(HARDENED_FLAKE8, encoding="utf-8")
        analyzer = Flake8Analyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0
        assert analyzer.infos[0].max_line_length == 88

    def test_setup_cfg_flake8_section(self, tmp_path: Path):
        (tmp_path / "setup.cfg").write_text(
            "[metadata]\nname = demo\n\n[flake8]\nignore = *\n",
            encoding="utf-8",
        )
        analyzer = Flake8Analyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "ignore_all" for f in findings)

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = Flake8Analyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.config_files == 0

    def test_finding_format(self):
        finding = Flake8Finding(
            kind="disabled_security_rules",
            severity="high",
            message="test message",
            path=".flake8",
            lineno=3,
            line="ignore = S101",
        )
        assert ".flake8:3" in finding.format()
        assert "test message" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = Flake8Analyzer(".")
        template = analyzer.generate_hardened_template()
        assert "[flake8]" in template
        assert "max-line-length = 88" in template

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / ".flake8").write_text(
            "[flake8]\nignore = S101\n",
            encoding="utf-8",
        )
        analyzer = Flake8Analyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Flake8 analysis:" in context
        assert "bandit" in context or "S101" in context or "security" in context

    def test_project_health_integration(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / ".flake8").write_text(
            "[flake8]\nignore = S101\n",
            encoding="utf-8",
        )
        report = ProjectHealth(str(tmp_path)).analyze()
        flake8 = next(c for c in report.categories if c.name == "flake8")
        assert flake8.score < 100.0
        assert flake8.details.get("findings", 0) > 0
