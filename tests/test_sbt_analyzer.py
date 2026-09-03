"""Tests for SbtAnalyzer."""

from pathlib import Path

from devai.sbt_analyzer import SbtAnalyzer, SbtFinding


INSECURE_BUILD_SBT = """\
ThisBuild / scalaVersion := "2.13.14"

lazy val root = (project in file("."))
  .settings(
  name := "my-app",
  publishCredentials := Credentials("realm", "repo.example.com", "deploy", "secret-token-12345"),
  publishTo := Some("releases" at "http://insecure.example.com/releases"),
  resolvers += "Insecure" at "http://insecure.example.com/maven",
  libraryDependencies ++= Seq(
    "com.example" % "lib" % "latest",
    "com.private" % "dep" % "1.0" from "https://user:pass@github.com/private/deps.git#master"
  )
)
"""

INSECURE_CREDENTIALS = """\
realm=My Realm
host=repo.example.com
user=deploy
password=hardcoded-secret-password
"""

HARDENED_BUILD_SBT = """\
ThisBuild / scalaVersion := "2.13.14"
ThisBuild / version := "0.1.0-SNAPSHOT"

lazy val root = (project in file("."))
  .settings(
    name := "my-app",
    libraryDependencies ++= Seq(
      "com.typesafe.akka" %% "akka-actor" % "2.8.5"
    )
  )
"""


class TestSbtAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = SbtAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_build_sbt(self, tmp_path: Path):
        (tmp_path / "build.sbt").write_text(HARDENED_BUILD_SBT, encoding="utf-8")
        analyzer = SbtAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "build.sbt").write_text(INSECURE_BUILD_SBT, encoding="utf-8")
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "credentials.sbt").write_text(INSECURE_CREDENTIALS, encoding="utf-8")
        analyzer = SbtAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds or "publish_credentials" in kinds
        assert "insecure_http" in kinds
        assert "scm_credentials" in kinds
        assert analyzer.health_score() < 100.0

    def test_hardened_config_has_no_findings(self, tmp_path: Path):
        (tmp_path / "build.sbt").write_text(HARDENED_BUILD_SBT, encoding="utf-8")
        analyzer = SbtAnalyzer(str(tmp_path))
        assert analyzer.stats.findings == 0
        assert analyzer.health_score() == 100.0

    def test_generate_hardened_config(self):
        analyzer = SbtAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "scalaVersion" in config
        assert "https://" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "build.sbt").write_text(INSECURE_BUILD_SBT, encoding="utf-8")
        analyzer = SbtAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "sbt analysis:" in context
        assert "health score:" in context

    def test_finding_format(self):
        finding = SbtFinding(
            kind="test",
            severity="high",
            message="test message",
            path="build.sbt",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "build.sbt:1" in finding.format()
