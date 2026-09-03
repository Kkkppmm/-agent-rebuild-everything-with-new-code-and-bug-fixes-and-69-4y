"""Tests for PnpmAnalyzer."""

import json
from pathlib import Path

from devai.pnpm_analyzer import PnpmAnalyzer, PnpmFinding


INSECURE_PNPM_WORKSPACE = """\
packages:
  - "packages/*"
  - "apps/*"
# registry override with secret
registry=https://registry.example.com
//registry.example.com/:_authToken=npm_hardcoded_token_abcdefghijklmnopqrst
"""

INSECURE_NPMRC = """\
registry=https://registry.npmjs.org/
strict-ssl=false
verify-store-integrity=false
shamefully-hoist=true
auto-install-peers=true
strict-peer-dependencies=false
"""

INSECURE_PNPMFILE = """\
module.exports = {
  hooks: {
    readPackage(pkg) {
      eval('process.env.SECRET = "leaked"');
      return pkg;
    }
  }
};
"""

INSECURE_PACKAGE_JSON = {
    "name": "demo",
    "packageManager": "pnpm@9.0.0",
    "pnpm": {
        "overrides": {
            "lodash": "*",
            "debug": "git+https://github.com/debug-js/debug.git#main",
        }
    },
}

HARDENED_PNPM = """\
packages:
  - "packages/*"
"""


class TestPnpmAnalyzer:
    def test_detects_insecure_pnpm_workspace(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(INSECURE_PNPM_WORKSPACE, encoding="utf-8")
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "npm_token" in kinds

    def test_detects_insecure_npmrc(self, tmp_path: Path):
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_ssl" in kinds
        assert "shamefully_hoist" in kinds

    def test_detects_insecure_pnpmfile(self, tmp_path: Path):
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        (tmp_path / ".pnpmfile.cjs").write_text(INSECURE_PNPMFILE, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "pnpmfile_eval" in kinds

    def test_detects_pnpm_overrides(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps(INSECURE_PACKAGE_JSON, indent=2), encoding="utf-8"
        )
        analyzer = PnpmAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "wildcard_override" in kinds
        assert "unpinned_git_dep" in kinds
        assert "missing_lockfile" in kinds

    def test_hardened_config_has_good_score(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text(HARDENED_PNPM, encoding="utf-8")
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = PnpmAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Pnpm configs: none found"

    def test_generate_hardened_config(self):
        config = PnpmAnalyzer(".").generate_hardened_config()
        assert "verify-store-integrity=true" in config
        assert "strict-peer-dependencies=true" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
        (tmp_path / ".npmrc").write_text(INSECURE_NPMRC, encoding="utf-8")
        analyzer = PnpmAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Pnpm analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = PnpmFinding(
            kind="insecure_ssl",
            severity="high",
            message="store verification disabled",
            path=".npmrc",
            lineno=2,
        )
        assert "[high] .npmrc:2" in finding.format()
