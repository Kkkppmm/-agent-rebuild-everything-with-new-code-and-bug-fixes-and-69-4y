"""Tests for TurboAnalyzer."""

from pathlib import Path

from devai.turbo_analyzer import TurboAnalyzer, TurboFinding


INSECURE_TURBO = """\
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": [".env", ".ssh/id_rsa"],
  "globalEnv": ["NODE_ENV", "DATABASE_PASSWORD", "AWS_SECRET_ACCESS_KEY"],
  "globalPassThroughEnv": ["GITHUB_TOKEN", "NPM_TOKEN"],
  "remoteCache": {
    "signature": false,
    "teamId": "api_key=hardcoded-secret-token-12345"
  },
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "inputs": ["src/**", ".env", "credentials.json"],
      "outputs": ["dist/**"],
      "passThroughEnv": ["STRIPE_SECRET_KEY"],
      "env": ["API_KEY"]
    },
    "deploy": {
      "cache": false,
      "dependsOn": ["build"]
    }
  }
}
"""

INSECURE_TURBO_JSONC = """\
{
  // Remote cache over HTTP
  "remoteCache": {
    "url": "http://cache.example.com",
    "dangerouslyDisableSignature": true
  },
  "tasks": {
    "setup": {
      "inputs": ["package.json"],
      "env": ["TOKEN"]
    }
  }
}
"""

HARDENED_TURBO = """\
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": [".env.example"],
  "globalEnv": ["NODE_ENV", "CI"],
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "inputs": ["src/**", "package.json"],
      "outputs": ["dist/**"],
      "env": ["NODE_ENV"]
    },
    "test": {
      "dependsOn": ["build"],
      "cache": true
    }
  },
  "remoteCache": {
    "signature": true
  }
}
"""


class TestTurboAnalyzer:
    def test_detects_insecure_turbo_json(self, tmp_path: Path):
        (tmp_path / "turbo.json").write_text(INSECURE_TURBO, encoding="utf-8")
        analyzer = TurboAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "sensitive_path" in kinds
        assert "global_pass_through_secret" in kinds
        assert "global_env_secret" in kinds
        assert "task_pass_through_secret" in kinds
        assert "disabled_signature" in kinds
        assert "hardcoded_secret" in kinds
        assert "cache_disabled" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_turbo_jsonc(self, tmp_path: Path):
        (tmp_path / "turbo.jsonc").write_text(INSECURE_TURBO_JSONC, encoding="utf-8")
        analyzer = TurboAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "disabled_signature" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "turbo.json").write_text(HARDENED_TURBO, encoding="utf-8")
        analyzer = TurboAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_config_returns_full_score(self, tmp_path: Path):
        analyzer = TurboAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = TurboFinding(
            kind="test",
            severity="high",
            message="test message",
            path="turbo.json",
            lineno=1,
        )
        assert "[high] turbo.json:1" in finding.format()

    def test_generate_hardened_config(self):
        config = TurboAnalyzer(".").generate_hardened_config()
        assert "signature" in config
        assert "globalEnv" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "turbo.json").write_text(INSECURE_TURBO, encoding="utf-8")
        analyzer = TurboAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Turbo analysis:" in context
        assert "findings:" in context
