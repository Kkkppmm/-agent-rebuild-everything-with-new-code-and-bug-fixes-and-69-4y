"""AWSCodePipelineAnalyzer — audit AWS CodePipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPELINE_FILENAMES = (
    "pipeline.json",
    "codepipeline.json",
    "codepipeline.yml",
    "codepipeline.yaml",
)
PIPELINE_SUFFIXES = ("-pipeline.json", "-pipeline.yml", "-pipeline.yaml")
PIPELINE_DIRS = (".aws", "aws", "ci/aws", "codepipeline", ".codepipeline", "infrastructure")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|OAuthToken)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_CONFIG_SECRET_PATTERN = re.compile(
    r"[\"'](?:OAuthToken|GitHubToken|BitbucketToken|Token|Password|Secret|ApiKey|AccessKey)"
    r"[\"']\s*:\s*[\"'][^\"'{}\s][^\"']+[\"']",
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
MISSING_ENCRYPTION_PATTERN = re.compile(
    r"\"artifactStore\"\s*:\s*\{[^}]*\"type\"\s*:\s*\"S3\"[^}]*\}",
    re.IGNORECASE | re.DOTALL,
)
ENCRYPTION_KEY_PATTERN = re.compile(
    r"\"encryptionKey\"\s*:\s*\{",
    re.IGNORECASE,
)
PUBLIC_S3_ACL_PATTERN = re.compile(
    r"(?:public-read|public-read-write|authenticated-read)",
    re.IGNORECASE,
)
CROSS_ACCOUNT_ROLE_PATTERN = re.compile(
    r"\"roleArn\"\s*:\s*\"arn:aws:iam::\d{12}:role/[^\"]+\"",
    re.IGNORECASE,
)
ADMIN_POLICY_PATTERN = re.compile(
    r"(?:AdministratorAccess|PowerUserAccess|IAMFullAccess|AmazonS3FullAccess)",
    re.IGNORECASE,
)
VARIABLE_INJECTION_PATTERN = re.compile(
    r"#\{(?:variables\.|codepipeline\.|source\.|env\.)[^}]+\}",
    re.IGNORECASE,
)
WEBHOOK_SECRET_PATTERN = re.compile(
    r"[\"']SecretToken[\"']\s*:\s*[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
UNENCRYPTED_S3_ARTIFACT_PATTERN = re.compile(
    r"\"location\"\s*:\s*\"[^\"]+\"(?![^}]*\"encryptionKey\")",
    re.IGNORECASE,
)
INSECURE_BRANCH_PATTERN = re.compile(
    r"[\"']BranchName[\"']\s*:\s*[\"']\*[\"']",
    re.IGNORECASE,
)
POLL_SOURCE_CHANGES_PATTERN = re.compile(
    r"[\"']PollForSourceChanges[\"']\s*:\s*\"?true\"?",
    re.IGNORECASE,
)
SECURITY_STAGE_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks|approval)",
    re.IGNORECASE,
)
STAGE_NAME_PATTERN = re.compile(r"[\"']name[\"']\s*:\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
ACTION_TYPE_PATTERN = re.compile(
    r"[\"']actionTypeId[\"']\s*:\s*\{[^}]*\"category\"\s*:\s*\"([^\"]+)\"",
    re.IGNORECASE | re.DOTALL,
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
    """Parsed metadata about a CodePipeline config."""

    path: str
    stages: list[str] = field(default_factory=list)
    actions: int = 0
    has_encryption: bool = False
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


def _is_pipeline_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in PIPELINE_FILENAMES:
        return True
    if any(lower.endswith(suffix) for suffix in PIPELINE_SUFFIXES):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(PIPELINE_DIRS) and lower.endswith((".json", ".yml", ".yaml")):
        if "pipeline" in lower or "codepipeline" in lower:
            return True
    if lower.endswith((".json", ".yml", ".yaml")):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if "AWS::CodePipeline::Pipeline" in content or '"pipeline"' in content:
                return True
        except OSError:
            pass
    return False


class AWSCodePipelineAnalyzer:
    """Audit AWS CodePipeline configs for hardcoded secrets, unencrypted artifacts, and weak IAM.

    Scans pipeline JSON/YAML for plaintext OAuth tokens, missing KMS encryption on artifact
    stores, wildcard branch sources, variable injection in action configuration, and
    overly permissive IAM policy references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AWSCodePipelineFinding] | None = None
        self._stats: AWSCodePipelineStats | None = None
        self._infos: list[AWSCodePipelineInfo] | None = None

    def files(self) -> list[Path]:
        """Return CodePipeline config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pipeline_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AWSCodePipelineFinding], AWSCodePipelineInfo]:
        findings: list[AWSCodePipelineFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AWSCodePipelineInfo(path=rel)

        content = "\n".join(raw_lines)
        info = AWSCodePipelineInfo(path=rel, lines=len(raw_lines))
        info.has_encryption = bool(ENCRYPTION_KEY_PATTERN.search(content))
        info.stages = [m.group(1) for m in STAGE_NAME_PATTERN.finditer(content)]
        info.actions = len(ACTION_TYPE_PATTERN.findall(content))

        stage_names = []
        has_security_stage = False
        artifact_store_blocks = 0
        encrypted_stores = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            stage_match = STAGE_NAME_PATTERN.search(raw)
            if stage_match and '"stages"' in content:
                stage_name = stage_match.group(1)
                if stage_name not in stage_names:
                    stage_names.append(stage_name)
                    if SECURITY_STAGE_PATTERN.search(stage_name):
                        has_security_stage = True

            if '"artifactStore"' in raw or '"ArtifactStore"' in raw:
                artifact_store_blocks += 1

            if ENCRYPTION_KEY_PATTERN.search(raw):
                encrypted_stores += 1

            if HARDCODED_SECRET_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret in CodePipeline config — use Secrets Manager or SSM Parameter Store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_CONFIG_SECRET_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="config_secret",
                        severity="high",
                        message="Plaintext token/password in action configuration — use Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="Hardcoded AWS access key — use IAM roles and Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WEBHOOK_SECRET_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="webhook_secret",
                        severity="high",
                        message="Plaintext webhook SecretToken — store in Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ADMIN_POLICY_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="overly_permissive_policy",
                        severity="high",
                        message="Overly permissive IAM policy reference — apply least privilege",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLIC_S3_ACL_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="public_s3_acl",
                        severity="high",
                        message="Public S3 ACL on artifact store — restrict bucket access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_BRANCH_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="wildcard_branch",
                        severity="medium",
                        message="Wildcard branch source (*) — restrict to protected branches",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if VARIABLE_INJECTION_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="variable_injection",
                        severity="medium",
                        message="CodePipeline variable interpolation — validate untrusted inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="Insecure HTTP URL — use HTTPS for remote resources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if POLL_SOURCE_CHANGES_PATTERN.search(raw):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="poll_source_changes",
                        severity="low",
                        message="PollForSourceChanges enabled — prefer event-driven triggers (webhooks/EventBridge)",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        info.stages = stage_names[:20]

        if '"artifactStore"' in content and not info.has_encryption:
            findings.append(
                AWSCodePipelineFinding(
                    kind="unencrypted_artifacts",
                    severity="high",
                    message="Artifact store missing KMS encryptionKey — enable SSE-KMS for pipeline artifacts",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if artifact_store_blocks > encrypted_stores and encrypted_stores == 0 and '"artifactStore"' in content:
            if not any(f.kind == "unencrypted_artifacts" for f in findings):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="unencrypted_artifacts",
                        severity="high",
                        message="S3 artifact store without encryptionKey — enable KMS encryption",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if info.actions >= 3 and not has_security_stage:
            findings.append(
                AWSCodePipelineFinding(
                    kind="missing_security_stage",
                    severity="low",
                    message="Pipeline has multiple actions but no security/approval stage",
                    path=rel,
                    lineno=1,
                    line="",
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
        """Return parsed config metadata."""
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
        """Scaffold a hardened CodePipeline JSON template."""
        return """\
{
  "pipeline": {
    "name": "MySecurePipeline",
    "roleArn": "arn:aws:iam::ACCOUNT_ID:role/CodePipelineServiceRole",
    "artifactStore": {
      "type": "S3",
      "location": "my-secure-artifacts-bucket",
      "encryptionKey": {
        "id": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID",
        "type": "KMS"
      }
    },
    "stages": [
      {
        "name": "Source",
        "actions": [
          {
            "name": "SourceAction",
            "actionTypeId": {
              "category": "Source",
              "owner": "AWS",
              "provider": "CodeCommit",
              "version": "1"
            },
            "configuration": {
              "RepositoryName": "my-repo",
              "BranchName": "main",
              "PollForSourceChanges": "false"
            },
            "outputArtifacts": [{ "name": "SourceOutput" }]
          }
        ]
      },
      {
        "name": "Security",
        "actions": [
          {
            "name": "SecurityScan",
            "actionTypeId": {
              "category": "Build",
              "owner": "AWS",
              "provider": "CodeBuild",
              "version": "1"
            },
            "configuration": {
              "ProjectName": "security-scan-project"
            },
            "inputArtifacts": [{ "name": "SourceOutput" }]
          }
        ]
      },
      {
        "name": "Deploy",
        "actions": [
          {
            "name": "ManualApproval",
            "actionTypeId": {
              "category": "Approval",
              "owner": "AWS",
              "provider": "Manual",
              "version": "1"
            },
            "configuration": {
              "CustomData": "Approve production deployment"
            }
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
            f"AWS CodePipeline: {stats.pipelines} pipeline(s), "
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
            lines.append(
                f"  - {info.path}: stages=[{stages}], actions={info.actions}, "
                f"encrypted={info.has_encryption}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
