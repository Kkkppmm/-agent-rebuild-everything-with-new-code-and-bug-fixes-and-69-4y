"""Tests for v6.97.0 PulumiAnalyzer integration."""

from pathlib import Path

from devai import DevAI, PulumiAnalyzer
from devai.project_health import ProjectHealth

HARDENED_PULUMI_YAML = """\
name: secure-app
runtime: python
description: Hardened Pulumi project

backend:
  url: s3://my-org-pulumi-state?region=us-east-1&awssdk=v2

config:
  pulumi:tags:
    value:
      environment: production
"""

HARDENED_MAIN_PY = """\
import pulumi
import pulumi_aws as aws

config = pulumi.Config()
db_password = config.require_secret("dbPassword")

bucket = aws.s3.Bucket(
    "data-bucket",
    acl="private",
    server_side_encryption_configuration={
        "rule": {
            "apply_server_side_encryption_by_default": {
                "sse_algorithm": "AES256",
            },
        },
    },
    opts=pulumi.ResourceOptions(protect=True),
)
"""

UNSAFE_PULUMI_YAML = """\
name: insecure-app
runtime: python

config:
  aws:accessKey:
    value: AKIAIOSFODNN7EXAMPLE
  aws:secretKey:
    value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  dbPassword:
    value: SuperSecret123!
"""

UNSAFE_STACK_YAML = """\
config:
  myapp:api_key: sk-live-1234567890abcdef
  myapp:db_password: plaintext-password-here
  pulumi:log_verbosity: 11
encryptionsalt: v1:abc123:xyz789
"""

UNSAFE_MAIN_PY = """\
import pulumi
import pulumi_aws as aws

db = aws.rds.Instance(
    "database",
    engine="postgres",
    instance_class="db.t3.micro",
    password="hardcoded-password-123",
    publicly_accessible=True,
    skip_final_snapshot=True,
    opts=pulumi.ResourceOptions(protect=False),
)

sg = aws.ec2.SecurityGroup(
    "open-sg",
    ingress=[{
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"],
    }],
)

container = aws.ecs.TaskDefinition(
    "app",
    container_definitions=[{
        "name": "web",
        "image": "nginx:latest",
    }],
)

provisioner = pulumi.Command(
    "bootstrap",
    create="curl https://install.example.com/script.sh | bash",
)
"""


class TestPulumiAnalyzer:
    def test_finds_no_high_issues_in_hardened_config(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(HARDENED_PULUMI_YAML, encoding="utf-8")
        (tmp_path / "__main__.py").write_text(HARDENED_MAIN_PY, encoding="utf-8")
        analyzer = PulumiAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        high = [f for f in findings if f.severity == "high"]
        assert high == []
        assert analyzer.stats.files >= 2
        assert analyzer.health_score() == 100.0

    def test_detects_unsafe_config(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(UNSAFE_PULUMI_YAML, encoding="utf-8")
        (tmp_path / "Pulumi.dev.yaml").write_text(UNSAFE_STACK_YAML, encoding="utf-8")
        (tmp_path / "__main__.py").write_text(UNSAFE_MAIN_PY, encoding="utf-8")
        analyzer = PulumiAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "plaintext_stack_secret" in kinds
        assert "hardcoded_aws_key" in kinds
        assert "public_access" in kinds
        assert "open_security_group" in kinds
        assert "skip_final_snapshot" in kinds
        assert "protect_disabled" in kinds
        assert "latest_image_tag" in kinds
        assert "curl_pipe_shell" in kinds
        assert "passphrase_in_config" in kinds
        assert "verbose_logging" in kinds
        assert analyzer.stats.high_severity >= 5
        assert analyzer.health_score() < 50.0

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(UNSAFE_PULUMI_YAML, encoding="utf-8")
        analyzer = PulumiAnalyzer(str(tmp_path))
        assert "Pulumi:" in analyzer.summary()
        assert "Pulumi project analysis" in analyzer.to_context()

    def test_hardened_template(self):
        template = PulumiAnalyzer(".").generate_hardened_template()
        assert "s3://" in template
        assert "--secret" in template

    def test_devai_facade(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(UNSAFE_PULUMI_YAML, encoding="utf-8")
        ai = DevAI.mock()
        analyzer = ai.pulumi(str(tmp_path))
        assert isinstance(analyzer, PulumiAnalyzer)
        assert analyzer.stats.findings > 0

    def test_project_health_integration(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(UNSAFE_PULUMI_YAML, encoding="utf-8")
        health = ProjectHealth(str(tmp_path)).analyze()
        names = {cat.name for cat in health.categories}
        assert "pulumi" in names
        pulumi_cat = next(cat for cat in health.categories if cat.name == "pulumi")
        assert pulumi_cat.score < 100.0

    def test_detects_missing_backend(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(
            "name: minimal\nruntime: python\n",
            encoding="utf-8",
        )
        analyzer = PulumiAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "missing_backend" in kinds

    def test_detects_insecure_backend(self, tmp_path: Path):
        (tmp_path / "Pulumi.yaml").write_text(
            """\
name: bad-backend
runtime: python
backend:
  url: http://pulumi-state.example.com
  secure: false
""",
            encoding="utf-8",
        )
        analyzer = PulumiAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "insecure_http_backend" in kinds
        assert "secure_disabled" in kinds
