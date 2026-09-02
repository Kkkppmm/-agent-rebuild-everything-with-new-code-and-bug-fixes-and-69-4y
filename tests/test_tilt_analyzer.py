"""Tests for TiltAnalyzer."""

from pathlib import Path

from devai.tilt_analyzer import TiltAnalyzer, TiltFinding


INSECURE_TILTFILE = """\
allow_k8s_contexts('production')

default_registry('http://registry.internal:5000', host_from_cluster='registry.internal:5000')

secret_settings(disable_scrub=True)

docker_build(
    'app',
    '.',
    dockerfile='Dockerfile',
    live_update=[
        sync('./.env', '/app/.env'),
    ],
    build_args={'api_key': 'sk-live-hardcoded-secret'},
)

k8s_yaml('k8s/')

k8s_resource(
    'app',
    port_forwards='0:0',
    labels=['app'],
)

local_resource(
    'setup',
    'curl https://example.com/install.sh | bash',
    deps=['Tiltfile'],
)

custom_build(
    'sidecar',
    'docker build -t $EXPECTED_REF .',
    ['/var/run/docker.sock'],
    image='nginx:latest',
)
"""

HARDENED_TILTFILE = """\
allow_k8s_contexts('docker-desktop', 'kind-kind')

default_registry('ghcr.io/org')

docker_build(
    'app',
    '.',
    dockerfile='Dockerfile',
    live_update=[
        sync('./src', '/app/src'),
        run('pip install -r requirements.txt', trigger=['requirements.txt']),
    ],
)

k8s_yaml('k8s/')

k8s_resource(
    'app',
    port_forwards='8080:8080',
    labels=['app'],
)
"""


class TestTiltAnalyzer:
    def test_no_configs_returns_perfect_score(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        analyzer = TiltAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 0
        assert analyzer.health_score() == 100.0

    def test_detects_insecure_patterns(self, tmp_path: Path):
        (tmp_path / "Tiltfile").write_text(INSECURE_TILTFILE, encoding="utf-8")
        analyzer = TiltAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "latest_image_tag" in kinds
        assert "docker_socket_mount" in kinds
        assert "curl_pipe_shell" in kinds
        assert "secret_scrub_disabled" in kinds
        assert "production_kube_context" in kinds
        assert analyzer.stats.configs == 1
        assert analyzer.stats.high_severity > 0

    def test_hardened_config_scores_well(self, tmp_path: Path):
        (tmp_path / "Tiltfile").write_text(HARDENED_TILTFILE, encoding="utf-8")
        analyzer = TiltAnalyzer(str(tmp_path))
        assert analyzer.health_score() >= 90.0
        assert analyzer.stats.findings == 0

    def test_finding_format(self):
        finding = TiltFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="Tiltfile",
            lineno=10,
            line="api_key='secret'",
        )
        assert "Tiltfile:10" in finding.format()

    def test_generate_hardened_config(self):
        analyzer = TiltAnalyzer(".")
        config = analyzer.generate_hardened_config()
        assert "allow_k8s_contexts" in config
        assert "docker_build" in config

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "Tiltfile").write_text(HARDENED_TILTFILE, encoding="utf-8")
        analyzer = TiltAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Tilt analysis:" in context
        assert "health score" in context

    def test_detects_tiltfile_extension(self, tmp_path: Path):
        (tmp_path / "Tiltfile.dev").write_text(
            "docker_build('app', '.')\nk8s_yaml('k8s/')\n",
            encoding="utf-8",
        )
        analyzer = TiltAnalyzer(str(tmp_path))
        assert analyzer.stats.configs == 1
