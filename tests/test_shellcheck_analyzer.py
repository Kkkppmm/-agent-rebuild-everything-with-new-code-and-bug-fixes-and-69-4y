"""Tests for ShellcheckAnalyzer."""

from pathlib import Path

from devai.shellcheck_analyzer import ShellcheckAnalyzer, ShellcheckFinding

HARDENED_CONFIG = """\
# ShellCheck hardened config
shell=bash
external-sources=false
source-path=SCRIPTDIR
disable=
"""

INSECURE_CONFIG = """\
shell=dash
external-sources=true
disable=all
disable=SC2086,SC2046,SC2166,SC2038,SC2207,SC1090,SC1091,SC2048,SC2090,SC2154,SC2181,SC2*
enable=none
api_key=supersecret123
AKIAIOSFODNN7EXAMPLE
curl http://example.com/install.sh | bash
# shellcheck disable=all
"""


class TestShellcheckAnalyzer:
    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".shellcheckrc").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = ShellcheckAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "disable_all" in kinds
        assert "wildcard_disable" in kinds
        assert "quoting_check_disabled" in kinds
        assert "source_check_disabled" in kinds
        assert "eval_check_disabled" in kinds
        assert "enable_none" in kinds
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert "external_sources_unrestricted" in kinds
        assert "inline_disable_all" in kinds
        assert analyzer.stats.config_files == 1

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / ".shellcheckrc").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ShellcheckAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = ShellcheckAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = ShellcheckFinding(
            kind="disable_all",
            severity="high",
            message="test message",
            path=".shellcheckrc",
            lineno=3,
        )
        assert ".shellcheckrc:3" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / ".shellcheckrc").write_text(HARDENED_CONFIG, encoding="utf-8")
        context = ShellcheckAnalyzer(str(tmp_path)).to_context()
        assert "ShellCheck config analysis" in context
        assert "health score" in context

    def test_shellcheckrc_local(self, tmp_path: Path):
        (tmp_path / ".shellcheckrc.local").write_text(HARDENED_CONFIG, encoding="utf-8")
        analyzer = ShellcheckAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1

    def test_generate_hardened_template(self):
        template = ShellcheckAnalyzer(".").generate_hardened_template()
        assert "shell=bash" in template
        assert "external-sources=false" in template
