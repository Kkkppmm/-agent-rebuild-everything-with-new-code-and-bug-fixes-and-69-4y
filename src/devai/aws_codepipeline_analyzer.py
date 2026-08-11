"""AWSCodePipelineAnalyzer — audit AWS CodePipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPELINE_FILENAMES = (
    "pipeline.json",
    "codepipeline.json",
    "codepipeline.yaml",
    "codepipeline.yml",
)
PIPELINE_DIRS = (".aws/codepipeline", "aws/codepipeline", "ci/aws", ".codepipeline", "codepipeline")
CODEPIPELINE_RESOURCE_PATTERN = re.compile(
    r"AWS::CodePipeline::Pipeline",
    re.IGNORECASE,
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|oauth|credential|private[_-]?key)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_OAUTH_PATTERN = re.compile(
    r"[\"']?(?:OAuthToken|GitHubToken|AccessToken|ConnectionToken)[\"']?\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"[\"']?AKIA[0-9A-Z]{16}[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
WILDCARD_ROLE_PATTERN = re.compile(
    r"arn:aws:iam::\*\s*:\s*role/",
    re.IGNORECASE,
)
BROAD_ROLE_PATTERN = re.compile(
    r"roleArn\s*[:=]\s*[\"']arn:aws:iam::\d{12}:role/(?:admin|AdministratorAccess|PowerUser)",
    re.IGNORECASE,
)
MISSING_ENCRYPTION_KEY_PATTERN = re.compile(
    r"[\"']?(?:artifactStore|ArtifactStore)[\"']?\s*:",
    re.IGNORECASE,
)
ENCRYPTION_KEY_PRESENT_PATTERN = re.compile(
    r"[\"']?(?:encryptionKey|EncryptionKey)[\"']?\s*[:=]",
    re.IGNORECASE,
)
PUBLIC_S3_ACL_PATTERN = re.compile(
    r"(?:public-read|public-read-write|authenticated-read)",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?(?:CODEPIPELINE_EXECUTION_ID|CODEBUILD_[A-Z0-9_]+|AWS_[A-Z0-9_]+)\}?",
    re.IGNORECASE,
)
PIPELINE_VAR_INJECTION_PATTERN = re.compile(
    r"#{variables\.[^}]+}",
    re.IGNORECASE,
)
CROSS_ACCOUNT_ROLE_PATTERN = re.compile(
    r"roleArn\s*[:=]\s*[\"']arn:aws:iam::(?!123456789012)\d{12}:role/",
    re.IGNORECASE,
)
EXTERNAL_ID_ABSENT_PATTERN = re.compile(
    r"ExternalId\s*[:=]",
    re.IGNORECASE,
)
UNPINNED_ACTION_VERSION_PATTERN = re.compile(
    r"^\s*version\s*:\s*[\"']?1[\"']?\s*$",
    re.IGNORECASE,
)
POLL_SOURCE_PATTERN = re.compile(
    r"[\"']?PollForSourceChanges[\"']?\s*:\s*[\"']?true[\"']?\s*[,}]?",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r":latest\b",
    re.IGNORECASE,
)
INSECURE_S3_LOCATION_PATTERN = re.compile(
    r"location\s*[:=]\s*[\"'][a-z0-9.-]+\.s3\.amazonaws\.com",
    re.IGNORECASE,
)


@dataclass
class AWSCodePipelineFinding:
    """A security or best-practice issue in an AWS CodePipeline config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class AWSCodePipelineInfo:
    """Parsed metadata about a CodePipeline config file."""

    path: str
    stages: list[str] = field(default_factory=list)
    action_providers: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class AWSCodePipelineStats:
    """Aggregate AWS CodePipeline analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_codepipeline_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in PIPELINE_FILENAMES:
        return True
    if "codepipeline" in lower and lower.endswith((".json", ".yaml", ".yml")):
        return True
    parts_lower = [p.lower() for p in path.parts]
    for pipeline_dir in PIPELINE_DIRS:
        dir_parts = pipeline_dir.split("/")
        for i in range(len(parts_lower) - len(dir_parts) + 1):
            if parts_lower[i : i + len(dir_parts)] == dir_parts:
                if lower.endswith((".json", ".yaml", ".yml")):
                    return True
    if lower.endswith((".yaml", ".yml", ".json", ".template")):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            if CODEPIPELINE_RESOURCE_PATTERN.search(content):
                return True
        except OSError:
            pass
    return False


class AWSCodePipelineAnalyzer:
    """Audit AWS CodePipeline definitions for hardcoded secrets, weak artifact stores, and unsafe configs.

    Scans pipeline JSON/YAML and CloudFormation templates for plaintext OAuth tokens, missing KMS
    encryption on artifact stores, wildcard IAM roles, and pipeline variable injection.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AWSCodePipelineFinding] | None = None
        self._stats: AWSCodePipelineStats | None = None
        self._infos: list[AWSCodePipelineInfo] | None = None

    def files(self) -> list[Path]:
        """Return CodePipeline config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_codepipeline_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AWSCodePipelineFinding], AWSCodePipelineInfo]:
        findings: list[AWSCodePipelineFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AWSCodePipelineInfo(path=rel)

        info = AWSCodePipelineInfo(path=rel, lines=len(raw_lines))
        content = "\n".join(raw_lines)
        in_artifact_store = False
        has_encryption_key = ENCRYPTION_KEY_PRESENT_PATTERN.search(content) is not None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            stage_match = re.match(r"^\s*-?\s*name\s*:\s*[\"']?([^\"'\n,]+)", line, re.IGNORECASE)
            if stage_match and re.search(r"stages?\s*:", content, re.IGNORECASE):
                stage_name = stage_match.group(1).strip()
                if stage_name.lower() not in ("source", "build", "deploy", "test", "approval"):
                    if len(stage_name) < 40:
                        info.stages.append(stage_name)

            provider_match = re.search(
                r"provider\s*:\s*[\"']?([A-Za-z0-9]+)[\"']?",
                line,
                re.IGNORECASE,
            )
            if provider_match:
                provider = provider_match.group(1)
                if provider not in info.action_providers:
                    info.action_providers.append(provider)

            if re.match(r"^\s*artifactStore\s*:", line, re.IGNORECASE):
                in_artifact_store = True
            if in_artifact_store and re.match(r"^\s*(stages|actions)\s*:", line, re.IGNORECASE):
                in_artifact_store = False

            if HARDCODED_OAUTH_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="hardcoded_oauth_token",
                        severity="high",
                        message="plaintext OAuth/token in pipeline config — use CodeStar Connections or Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use IAM roles, Connections, or Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="plaintext_aws_key",
                        severity="high",
                        message="plaintext AWS access key — use IAM roles or instance profiles",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WILDCARD_ROLE_PATTERN.search(line) or BROAD_ROLE_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="overprivileged_role",
                        severity="high",
                        message="overly broad pipeline role ARN — scope to least-privilege IAM role",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CROSS_ACCOUNT_ROLE_PATTERN.search(line) and not EXTERNAL_ID_ABSENT_PATTERN.search(content):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="cross_account_no_external_id",
                        severity="medium",
                        message="cross-account role without ExternalId — add ExternalId for confused-deputy protection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLIC_S3_ACL_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="public_s3_acl",
                        severity="high",
                        message="overly permissive S3 ACL on artifact store — restrict bucket access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) or PIPELINE_VAR_INJECTION_PATTERN.search(line):
                if re.search(r"(?:commands?|configuration|UserParameters|EnvironmentVariables)", content, re.IGNORECASE):
                    findings.append(
                        AWSCodePipelineFinding(
                            kind="variable_injection",
                            severity="medium",
                            message="pipeline variable interpolated in action config — validate untrusted inputs",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS sources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_ACTION_VERSION_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="unpinned_action_version",
                        severity="low",
                        message="action version unpinned at '1' — document and review provider upgrades",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if POLL_SOURCE_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="poll_for_source",
                        severity="low",
                        message="PollForSourceChanges enabled — prefer webhooks/EventBridge for efficiency",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_S3_LOCATION_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="path_style_s3",
                        severity="low",
                        message="path-style S3 URL — prefer virtual-hosted-style bucket references",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if MISSING_ENCRYPTION_KEY_PATTERN.search(content) and not has_encryption_key:
            if re.search(r"artifactStore|ArtifactStore", content):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="missing_encryption_key",
                        severity="medium",
                        message="artifact store without KMS encryptionKey — enable SSE-KMS for pipeline artifacts",
                        path=rel,
                        lineno=1,
                        line="artifactStore",
                    )
                )

        return findings, info

    def analyze(self) -> list[AWSCodePipelineFinding]:
        """Scan CodePipeline configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AWSCodePipelineFinding] = []
        infos: list[AWSCodePipelineInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = AWSCodePipelineStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AWSCodePipelineStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AWSCodePipelineInfo]:
        """Return parsed pipeline metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no pipelines)."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened AWS CodePipeline JSON template."""
        return """\
{
  "pipeline": {
    "name": "HardenedPipeline",
    "roleArn": "arn:aws:iam::123456789012:role/CodePipelineServiceRole",
    "artifactStore": {
      "type": "S3",
      "location": "my-pipeline-artifacts",
      "encryptionKey": {
        "id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        "type": "KMS"
      }
    },
    "stages": [
      {
        "name": "Source",
        "actions": [
          {
            "name": "Source",
            "actionTypeId": {
              "category": "Source",
              "owner": "AWS",
              "provider": "CodeCommit",
              "version": "1"
            },
            "configuration": {
              "RepositoryName": "MyRepo",
              "BranchName": "main",
              "PollForSourceChanges": "false"
            },
            "outputArtifacts": [
              {
                "name": "SourceArtifact"
              }
            ]
          }
        ]
      },
      {
        "name": "Build",
        "actions": [
          {
            "name": "Build",
            "actionTypeId": {
              "category": "Build",
              "owner": "AWS",
              "provider": "CodeBuild",
              "version": "1"
            },
            "configuration": {
              "ProjectName": "MyBuildProject"
            },
            "inputArtifacts": [
              {
                "name": "SourceArtifact"
              }
            ],
            "outputArtifacts": [
              {
                "name": "BuildArtifact"
              }
            ]
          }
        ]
      }
    ]
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "AWS CodePipeline: none found"
        return (
            f"AWS CodePipeline: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "AWS CodePipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            providers = ", ".join(info.action_providers[:5]) or "none"
            lines.append(f"  - {info.path}: stages=[{stages}], providers=[{providers}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
