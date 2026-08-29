"""Tests for BiomeAnalyzer."""

from pathlib import Path

from devai.biome_analyzer import BiomeAnalyzer, BiomeFinding


INSECURE_BIOME = """\
{
  "$schema": "http://insecure.example.com/schema.json",
  "vcs": {
    "enabled": true,
    "useIgnoreFile": false
  },
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "security": {
        "noDangerouslySetInnerHtml": "off",
        "noGlobalEval": false
      },
      "suspicious": {
        "noDebugger": "off"
      }
    }
  }
}
"""

INSECURE_BIOME_SECRETS = """\
{
  "linter": {
    "enabled": true,
    "rules": { "recommended": true }
  },
  "api_key": "sk-live-hardcoded-secret-token-12345"
}
"""

HARDENED_BIOME = """\
{
  "$schema": "https://biomejs.dev/schemas/1.9.4/schema.json",
  "vcs": {
    "enabled": true,
    "clientKind": "git",
    "useIgnoreFile": true
  },
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "security": {
        "noDangerouslySetInnerHtml": "error",
        "noGlobalEval": "error"
      }
    }
  }
}
"""


class TestBiomeAnalyzer:
    def test_detects_insecure_biome_config(self, tmp_path: Path):
        (tmp_path / "biome.json").write_text(INSECURE_BIOME, encoding="utf-8")
        analyzer = BiomeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "disabled_security_rule" in kinds
        assert "vcs_ignore_disabled" in kinds
        assert analyzer.stats.high_severity >= 1

    def test_detects_hardcoded_secrets(self, tmp_path: Path):
        (tmp_path / "biome.json").write_text(INSECURE_BIOME_SECRETS, encoding="utf-8")
        analyzer = BiomeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "biome.json").write_text(HARDENED_BIOME, encoding="utf-8")
        analyzer = BiomeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = BiomeAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Biome: no config files found"

    def test_generate_hardened_template(self):
        config = BiomeAnalyzer(".").generate_hardened_template()
        assert "noDangerouslySetInnerHtml" in config
        assert "useIgnoreFile" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "biome.json").write_text(INSECURE_BIOME, encoding="utf-8")
        analyzer = BiomeAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Biome configuration analysis:" in context
        assert "insecure" in context.lower() or "disabled" in context.lower()

    def test_finding_format(self):
        finding = BiomeFinding(
            kind="test",
            severity="high",
            message="test message",
            path="biome.json",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "biome.json:1" in finding.format()

    def test_jsonc_config(self, tmp_path: Path):
        jsonc = """\
// biome.jsonc with comments
{
  "linter": {
    "rules": {
      "security": { "noGlobalEval": "off" }
    }
  }
}
"""
        (tmp_path / "biome.jsonc").write_text(jsonc, encoding="utf-8")
        analyzer = BiomeAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "disabled_security_rule" in kinds
