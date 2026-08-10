"""Tests for TravisCIAnalyzer."""

from pathlib import Path

from devai.travis_ci_analyzer import TravisCIAnalyzer, TravisCIFinding

INSECURE_TRAVIS = """
language: node_js
node_js:
  - node
sudo: required
env:
  - API_TOKEN=plaintext-secret-value
before_install:
  - curl -fsSL https://example.com/install.sh | bash
script:
  - echo $TRAVIS_PULL_REQUEST_BRANCH
deploy:
  provider: npm
  api_key: "npm-hardcoded-key"
  all_branches: true
"""

HARDENED_TRAVIS = """
language: python
python:
  - "3.12"
branches:
  only:
    - main
env:
  global:
    - CI=true
install:
  - pip install -e ".[dev]"
script:
  - python -m pytest
sudo: false
"""


class TestTravisCIAnalyzer:
    def test_no_config_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert analyzer.stats.config_files == 0
        assert analyzer.health_score() == 100.0
        assert "no config" in analyzer.summary().lower()

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(INSECURE_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "plaintext_secret" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sudo_required" in kinds
        assert "floating_node_version" in kinds
        assert "plaintext_deploy_key" in kinds
        assert "deploy_all_branches" in kinds
        assert "unquoted_travis_var" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert not any(f.severity == "high" for f in findings)
        assert analyzer.stats.config_files == 1
        assert analyzer.infos[0].language == "python"

    def test_detects_floating_python(self, tmp_path: Path):
        content = "language: python\npython:\n  - development\nscript: pytest\n"
        (tmp_path / ".travis.yml").write_text(content, encoding="utf-8")
        findings = TravisCIAnalyzer(str(tmp_path)).analyze()
        assert any(f.kind == "floating_python_version" for f in findings)

    def test_summary_context_and_template(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text(HARDENED_TRAVIS, encoding="utf-8")
        analyzer = TravisCIAnalyzer(str(tmp_path))
        assert "Travis CI:" in analyzer.summary()
        assert "Travis CI analysis" in analyzer.to_context()
        template = analyzer.generate_hardened_template()
        assert "language: python" in template
        assert "sudo: false" in template

    def test_finding_format(self):
        finding = TravisCIFinding(
            kind="curl_pipe_shell",
            severity="high",
            message="test message",
            path=".travis.yml",
            lineno=8,
            line="curl | bash",
        )
        assert "[high]" in finding.format()
        assert ".travis.yml:8" in finding.format()
