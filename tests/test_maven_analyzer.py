"""Tests for MavenAnalyzer."""

from pathlib import Path

from devai.maven_analyzer import MavenAnalyzer, MavenFinding


INSECURE_POM = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>

  <repositories>
    <repository>
      <id>insecure</id>
      <url>http://insecure-maven.example.com/maven2</url>
    </repository>
  </repositories>

  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>library</artifactId>
      <version>LATEST</version>
    </dependency>
    <dependency>
      <groupId>com.bad</groupId>
      <artifactId>artifact</artifactId>
      <version>RELEASE</version>
    </dependency>
  </dependencies>

  <scm>
    <connection>scm:git:https://user:hardcoded-password@github.com/example/repo.git</connection>
  </scm>

  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
        <configuration>
          <executable>sh</executable>
          <arguments>
            <argument>-c</argument>
            <argument>curl -s https://install.example.com/script.sh | bash</argument>
          </arguments>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
"""

INSECURE_SETTINGS = """\
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <mirrors>
    <mirror>
      <id>wildcard</id>
      <mirrorOf>*</mirrorOf>
      <url>https://mirror.example.com/maven2</url>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>deploy</id>
      <username>deployer</username>
      <password>hardcoded-deploy-password</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <properties>
        <maven.wagon.http.ssl.insecure>true</maven.wagon.http.ssl.insecure>
      </properties>
    </profile>
  </profiles>
</settings>
"""

HARDENED_POM = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>library</artifactId>
      <version>1.2.3</version>
    </dependency>
  </dependencies>
</project>
"""


class TestMavenAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = MavenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "pom.xml").write_text(INSECURE_POM, encoding="utf-8")
        (tmp_path / "settings.xml").write_text(INSECURE_SETTINGS, encoding="utf-8")
        analyzer = MavenAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "dynamic_version" in kinds
        assert "scm_credentials" in kinds
        assert "curl_pipe_shell" in kinds
        assert "wildcard_mirror" in kinds
        assert "insecure_ssl" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "pom.xml").write_text(HARDENED_POM, encoding="utf-8")
        analyzer = MavenAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "pom.xml").write_text(INSECURE_POM, encoding="utf-8")
        analyzer = MavenAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, MavenFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "pom.xml").write_text(INSECURE_POM, encoding="utf-8")
        analyzer = MavenAnalyzer(str(tmp_path))
        assert "Maven configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Maven analysis:" in context
        assert "artifacts:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = MavenAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "https://repo.maven.apache.org/maven2" in config
        assert "settings" in config

    def test_detects_mvn_config(self, tmp_path: Path):
        mvn_dir = tmp_path / ".mvn"
        mvn_dir.mkdir()
        (mvn_dir / "maven.config").write_text(
            "-Dmaven.wagon.http.ssl.allowall=true\n",
            encoding="utf-8",
        )
        analyzer = MavenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "insecure_ssl" in kinds
