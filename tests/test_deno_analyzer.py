"""Tests for DenoAnalyzer."""

from pathlib import Path

from devai.deno_analyzer import DenoAnalyzer, DenoFinding


INSECURE_DENO = """\
{
  "tasks": {
    "dev": "deno run --allow-all main.ts",
    "deploy": "deno run --allow-run --allow-net deploy.ts"
  },
  "imports": {
    "react": "npm:react@latest",
    "lodash": "http://insecure-cdn.example.com/lodash.js",
    "secret-lib": "git+https://user:password@github.com/org/repo.git#main"
  },
  "compilerOptions": {
    "lib": ["deno.window", "deno.unstable"]
  }
}
"""

INSECURE_DENO_JSONC = """\
{
  // Overly permissive
  "tasks": {
    "start": "deno run --allow-all --allow-run server.ts"
  },
  "imports": {
    "pkg": "jsr:@std/http@*"
  }
}
"""

HARDENED_DENO = """\
{
  "tasks": {
    "dev": "deno run --allow-net --allow-read=./src main.ts",
    "test": "deno test --allow-read=./src,./tests"
  },
  "imports": {
    "@std/": "jsr:@std/"
  },
  "compilerOptions": {
    "strict": true
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
        assert "insecure_http" in kinds
        assert "unpinned_import" in kinds
        assert "scm_credentials" in kinds
        assert "unstable_api" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_deno_jsonc(self, tmp_path: Path):
        (tmp_path / "deno.jsonc").write_text(INSECURE_DENO_JSONC, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "allow_all" in kinds
        assert "unpinned_import" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(HARDENED_DENO, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = DenoAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = DenoFinding(
            kind="test",
            severity="high",
            message="test message",
            path="deno.json",
            lineno=1,
        )
        assert "[high] deno.json:1" in finding.format()

    def test_generate_hardened_config(self):
        config = DenoAnalyzer(".").generate_hardened_config()
        assert "allow-net" in config
        assert "strict" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(INSECURE_DENO, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Deno analysis:" in context
        assert "findings:" in context
