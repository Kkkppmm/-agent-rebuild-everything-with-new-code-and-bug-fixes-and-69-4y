"""Tests for BazelAnalyzer."""

from pathlib import Path

from devai.bazel_analyzer import BazelAnalyzer, BazelFinding


INSECURE_BAZEL = """\
http_archive(
    name = "bad_dep",
    urls = ["http://insecure.example.com/archive.tar.gz"],
)

git_repository(
    name = "unpinned_git",
    remote = "https://github.com/example/repo.git",
)

genrule(
    name = "install_tool",
    outs = ["tool.sh"],
    cmd = "curl -s https://install.example.com/script.sh | bash",
    tags = ["no-sandbox", "requires-network"],
)

local_repository(
    name = "secrets_repo",
    path = "/home/user/.ssh/keys",
)

container_image(
    name = "privileged_image",
    privileged = True,
    docker_run_flags = "--privileged",
)

bind(
    name = "old_bind",
    actual = "//:something",
)

py_library(
    name = "secrets",
    srcs = ["lib.py"],
    data = ["config.txt"],
)

# secret in assignment
token = "hardcoded-token-value-for-tests"
api_key = "sk-live-hardcoded-secret-value"
"""

HARDENED_BAZEL = """\
module(
    name = "my_project",
    version = "1.0.0",
)

http_archive(
    name = "good_dep",
    urls = ["https://github.com/example/repo/archive/v1.0.0.tar.gz"],
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    strip_prefix = "repo-1.0.0",
)

git_repository(
    name = "pinned_git",
    remote = "https://github.com/example/repo.git",
    commit = "abc123def456",
)

genrule(
    name = "fetch_tool",
    outs = ["tool"],
    cmd = "cp $(location //tools:tool) $@",
    tags = ["manual"],
)
"""


class TestBazelAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = BazelAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "MODULE.bazel").write_text(INSECURE_BAZEL, encoding="utf-8")
        analyzer = BazelAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "http_archive_no_checksum" in kinds
        assert "git_repository_unpinned" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sandbox_disabled" in kinds
        assert "sensitive_local_path" in kinds
        assert "privileged_container" in kinds
        assert "bind_usage" in kinds
        assert "insecure_http" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "MODULE.bazel").write_text(HARDENED_BAZEL, encoding="utf-8")
        analyzer = BazelAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "BUILD.bazel").write_text(INSECURE_BAZEL, encoding="utf-8")
        analyzer = BazelAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, BazelFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "BUILD.bazel").write_text(INSECURE_BAZEL, encoding="utf-8")
        analyzer = BazelAnalyzer(str(tmp_path))
        assert "Bazel configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Bazel analysis:" in context
        assert "rules:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = BazelAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "sha256" in config
        assert "http_archive" in config

    def test_detects_bazelrc(self, tmp_path: Path):
        (tmp_path / ".bazelrc").write_text(
            "build --spawn_strategy=standalone\nbuild password=secret-value\n",
            encoding="utf-8",
        )
        analyzer = BazelAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "sandbox_strategy_disabled" in kinds
