"""Tests for MixAnalyzer."""

from pathlib import Path

from devai.mix_analyzer import MixAnalyzer, MixFinding


INSECURE_MIX_EXS = """\
defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [
      app: :my_app,
      version: "0.1.0",
      elixir: "~> 1.16",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix},
      {:private_dep, git: "https://deploy:secret-token@github.com/private/deps.git", branch: "master"},
      {:http_dep, git: "http://insecure.example/repo.git"},
      {:dangerous, only: :dev}
    ]
  end
end
"""

INSECURE_CONFIG = """\
import Config

config :my_app, api_key: "sk-live-hardcoded-secret-key-12345"
config :my_app, hex_api_key: "hex:abcdefghijklmnopqrstuvwxyz123456"
"""

HARDENED_MIX_EXS = """\
defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [
      app: :my_app,
      version: "0.1.0",
      elixir: "~> 1.16",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.0"},
      {:plug_cowboy, "~> 2.7"}
    ]
  end
end
"""


class TestMixAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MixAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_mix_exs(self, tmp_path: Path):
        (tmp_path / "mix.exs").write_text(HARDENED_MIX_EXS, encoding="utf-8")
        (tmp_path / "mix.lock").write_text("%% MIX LOCK\n", encoding="utf-8")
        analyzer = MixAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "mix.exs").write_text(INSECURE_MIX_EXS, encoding="utf-8")
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "dev.exs").write_text(INSECURE_CONFIG, encoding="utf-8")
        analyzer = MixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "unpinned_git_dep" in kinds
        assert "insecure_http" in kinds
        assert "loose_version" in kinds
        assert "config_secret" in kinds
        assert "missing_lock" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_has_no_high_findings(self, tmp_path: Path):
        (tmp_path / "mix.exs").write_text(HARDENED_MIX_EXS, encoding="utf-8")
        (tmp_path / "mix.lock").write_text("%% MIX LOCK\n", encoding="utf-8")
        analyzer = MixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self):
        finding = MixFinding(
            kind="test",
            severity="high",
            message="test message",
            path="mix.exs",
            lineno=1,
            line="test",
        )
        assert "mix.exs:1" in finding.format()

    def test_generate_hardened_config(self):
        analyzer = MixAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "HEX_API_KEY" in config
        assert "mix.lock" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "mix.exs").write_text(HARDENED_MIX_EXS, encoding="utf-8")
        (tmp_path / "mix.lock").write_text("%% MIX LOCK\n", encoding="utf-8")
        analyzer = MixAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Mix analysis:" in context
        assert "health score" in context
