"""AWSCodePipelineAnalyzer — audit AWS CodePipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPELINE_FILENAMES = (
    "pipeline.json",
    "pipeline.yml",
    "pipeline.yaml",
    "codepipeline.json",
    "codepipeline.yml",
    "codepipeline.yaml",
)
PIPELINE_DIRS = (".aws/codepipeline", "codepipeline", "pipelines", "infrastructure", ".aws")
PIPELINE_MARKERS = (
    "AWS::CodePipeline::Pipeline",
    "aws:codepipeline",
    "CodePipeline",
    "PipelineType",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"^\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|AWS_[A-Z0-9_]+)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"[\"']?AKIA[0-9A-Z]{16}[\"']?",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?(?:CODEPIPELINE_[A-Z0-9_]+|CODEBUILD_[A-Z0-9_]+|AWS_[A-Z0-9_]+)\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
ENCRYPTION_DISABLED_PATTERN = re.compile(
    r"(?:EncryptionDisabled|DisableArtifactEncryption)\s*:\s*true",
    re.IGNORECASE,
)
NO_ENCRYPTION_KEY_PATTERN = re.compile(
    r"(?:EncryptionKey|KmsKeyId)\s*:\s*(?:\"\"|''|none|null)\s*$",
    re.IGNORECASE,
)
KMS_KEY_ID_NONE_PATTERN = re.compile(
    r"^\s*Id\s*:\s*[\"']?none[\"']?\s*$",
    re.IGNORECASE,
)
PUBLIC_S3_ACL_PATTERN = re.compile(
    r"(?:public-read|public-read-write|authenticated-read)",
    re.IGNORECASE,
)
WILDCARD_IAM_ACTION_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*$",
)
WILDCARD_IAM_RESOURCE_PATTERN = re.compile(
    r"^\s*Resource\s*:\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
WILDCARD_IAM_ACTION_INLINE_PATTERN = re.compile(
    r"^\s*Action\s*:\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
CROSS_ACCOUNT_PATTERN = re.compile(
    r"(?:RoleArn|AssumeRoleArn)\s*:\s*[\"']?arn:aws:iam::\d{12}:",
    re.IGNORECASE,
)
APPROVAL_STAGE_PATTERN = re.compile(
    r"(?:Category|Provider)\s*:\s*[\"']?(?:Approval|Manual)",
    re.IGNORECASE,
)
PRODUCTION_STAGE_PATTERN = re.compile(
    r"(?:StageName|Name)\s*:\s*[\"']?(?:Prod|Production|Release)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
ENV_VAR_NAME_PATTERN = re.compile(
    r"^\s*(?:-\s*)?Name\s*:\s*[\"']?"
    r"(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|AWS_[A-Z0-9_]+|"
    r"api[_-]?token|password|passwd|secret|credential)"
    r"[\"']?\s*$",
    re.IGNORECASE,
)
ENV_VAR_VALUE_PATTERN = re.compile(
    r"^\s*(?:-\s*)?Value\s*:\s*[\"']([^\"'{}\s][^\"']*)[\"']\s*$",
    re.IGNORECASE,
)
UNENCRYPTED_ARTIFACT_STORE_PATTERN = re.compile(
    r"(?:Type|Location)\s*:\s*[\"']?S3[\"']?",
    re.IGNORECASE,
)
S3_VERSIONING_DISABLED_PATTERN = re.compile(
    r"VersioningConfiguration\s*:\s*\n\s+Status\s*:\s*Suspended",
    re.IGNORECASE | re.MULTILINE,
)
STAGE_NAME_PATTERN = re.compile(
    r"^\s*(?:StageName|Name)\s*:\s*[\"']?([A-Za-z0-9_-]+)[\"']?\s*$",
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
    has_approval: bool = False
    has_production: bool = False
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
    parts = {p.lower() for p in path.parts}
    if parts & set(PIPELINE_DIRS) and lower.endswith((".yml", ".yaml", ".json")):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if any(marker in content for marker in PIPELINE_MARKERS):
                return True
        except OSError:
            return False
    if lower.endswith((".pipeline.yml", ".pipeline.yaml", ".pipeline.json")):
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if "AWS::CodePipeline::Pipeline" in content:
            return True
    except OSError:
        return False
    return False


class AWSCodePipelineAnalyzer:
    """Audit AWS CodePipeline configs for hardcoded secrets, weak IAM, and unsafe stages.

    Scans CloudFormation and standalone pipeline YAML/JSON for plaintext credentials,
    disabled artifact encryption, wildcard IAM policies, and CODEPIPELINE_* variable injection.
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

        info = AWSCodePipelineInfo(path=rel, lines=len(raw_lines))
        in_env_variables = False
        has_security_stage = False
        pending_sensitive_env_name = False
        in_encryption_key_block = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            stage_match = STAGE_NAME_PATTERN.match(line)
            if stage_match:
                stage_name = stage_match.group(1)
                info.stages.append(stage_name)
                if APPROVAL_STAGE_PATTERN.search(line):
                    info.has_approval = True
                if PRODUCTION_STAGE_PATTERN.search(line):
                    info.has_production = True

            if APPROVAL_STAGE_PATTERN.search(line):
                info.has_approval = True

            if PRODUCTION_STAGE_PATTERN.search(line):
                info.has_production = True

            if SECURITY_STEP_PATTERN.search(line):
                has_security_stage = True

            if re.match(r"^\s*EnvironmentVariables\s*:\s*$", line, re.IGNORECASE):
                in_env_variables = True
                pending_sensitive_env_name = False
                continue

            if in_env_variables and ENV_VAR_NAME_PATTERN.match(line):
                pending_sensitive_env_name = True
                continue

            if in_env_variables and pending_sensitive_env_name:
                value_match = ENV_VAR_VALUE_PATTERN.match(line)
                if value_match:
                    value = value_match.group(1)
                    if AWS_ACCESS_KEY_PATTERN.search(value):
                        findings.append(
                            AWSCodePipelineFinding(
                                kind="plaintext_aws_key",
                                severity="high",
                                message="plaintext AWS access key — use IAM roles or Secrets Manager",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    elif not re.search(r"(?:true|false|null|\$\{)", value, re.IGNORECASE):
                        findings.append(
                            AWSCodePipelineFinding(
                                kind="hardcoded_secret",
                                severity="high",
                                message="hardcoded value in EnvironmentVariables — use Secrets Manager or SSM",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                pending_sensitive_env_name = False
                continue

            if re.match(r"^\s*(?:Stages|ArtifactStore|RoleArn|Pipeline)\s*:", line, re.IGNORECASE):
                in_env_variables = False
                pending_sensitive_env_name = False

            if in_env_variables and HARDCODED_ENV_VALUE_PATTERN.match(line):
                if not re.search(r"(?:true|false|null|\$\{)", line, re.IGNORECASE):
                    findings.append(
                        AWSCodePipelineFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded value in EnvironmentVariables — use Secrets Manager or SSM",
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
                        message="hardcoded credential — use AWS Secrets Manager or SSM Parameter Store",
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
                        message="plaintext AWS access key — use IAM roles or Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ENCRYPTION_DISABLED_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="encryption_disabled",
                        severity="high",
                        message="artifact encryption disabled — enable KMS encryption for pipeline artifacts",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.match(r"^\s*EncryptionKey\s*:\s*$", line, re.IGNORECASE):
                in_encryption_key_block = True
                continue

            if in_encryption_key_block and KMS_KEY_ID_NONE_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="missing_encryption_key",
                        severity="medium",
                        message="no KMS encryption key configured for artifacts — specify a customer-managed KMS key",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
                in_encryption_key_block = False
                continue

            if in_encryption_key_block and re.match(r"^\s*Type\s*:", line, re.IGNORECASE):
                in_encryption_key_block = False

            if NO_ENCRYPTION_KEY_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="missing_encryption_key",
                        severity="medium",
                        message="no KMS encryption key configured for artifacts — specify a customer-managed KMS key",
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
                        message="public S3 ACL on artifact store — restrict bucket access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WILDCARD_IAM_ACTION_PATTERN.match(line) or WILDCARD_IAM_ACTION_INLINE_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="wildcard_iam_action",
                        severity="high",
                        message="wildcard IAM Action (*) — apply least-privilege permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WILDCARD_IAM_RESOURCE_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="wildcard_iam_resource",
                        severity="medium",
                        message="wildcard IAM Resource (*) — scope to specific pipeline resources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and re.search(
                r"(?:Configuration|UserParameters|commands|script)", line, re.IGNORECASE
            ):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="script_injection",
                        severity="medium",
                        message="CODEPIPELINE_/CODEBUILD_ variable in action config — validate untrusted inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP URL — use HTTPS for external endpoints",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CROSS_ACCOUNT_PATTERN.search(line) and "Condition" not in line:
                findings.append(
                    AWSCodePipelineFinding(
                        kind="cross_account_role",
                        severity="medium",
                        message="cross-account IAM role without visible Condition — restrict with external ID or conditions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if S3_VERSIONING_DISABLED_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="s3_versioning_disabled",
                        severity="low",
                        message="S3 artifact bucket versioning suspended — enable versioning for audit trail",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.has_production and not info.has_approval:
            findings.append(
                AWSCodePipelineFinding(
                    kind="missing_approval",
                    severity="low",
                    message="production stage without manual approval — add an Approval action before deploy",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if not has_security_stage and info.stages:
            findings.append(
                AWSCodePipelineFinding(
                    kind="missing_security_stage",
                    severity="low",
                    message="no security scan stage detected — add a security/audit stage to the pipeline",
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

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
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
        """Scaffold a hardened AWS CodePipeline CloudFormation template."""
        return """\
# Generated by DevAI AWSCodePipelineAnalyzer
AWSTemplateFormatVersion: "2010-09-09"
Description: Hardened CodePipeline with KMS encryption and manual approval

Resources:
  PipelineArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !Ref PipelineKmsKey
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true

  PipelineKmsKey:
    Type: AWS::KMS::Key
    Properties:
      Description: KMS key for CodePipeline artifact encryption
      EnableKeyRotation: true

  ApplicationPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: !Sub "${AWS::StackName}-pipeline"
      RoleArn: !GetAtt PipelineServiceRole.Arn
      ArtifactStore:
        Type: S3
        Location: !Ref PipelineArtifactBucket
        EncryptionKey:
          Id: !GetAtt PipelineKmsKey.Arn
          Type: KMS
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId:
                Category: Source
                Owner: AWS
                Provider: CodeCommit
                Version: "1"
              OutputArtifacts:
                - Name: SourceOutput
              Configuration:
                RepositoryName: my-repo
                BranchName: main
        - Name: Build
          Actions:
            - Name: BuildAction
              ActionTypeId:
                Category: Build
                Owner: AWS
                Provider: CodeBuild
                Version: "1"
              InputArtifacts:
                - Name: SourceOutput
              OutputArtifacts:
                - Name: BuildOutput
              Configuration:
                ProjectName: !Ref BuildProject
        - Name: SecurityScan
          Actions:
            - Name: SecurityScan
              ActionTypeId:
                Category: Build
                Owner: AWS
                Provider: CodeBuild
                Version: "1"
              InputArtifacts:
                - Name: BuildOutput
              Configuration:
                ProjectName: !Ref SecurityScanProject
        - Name: Approval
          Actions:
            - Name: ManualApproval
              ActionTypeId:
                Category: Approval
                Owner: AWS
                Provider: Manual
                Version: "1"
              Configuration:
                CustomData: Approve deployment to production
        - Name: Production
          Actions:
            - Name: Deploy
              ActionTypeId:
                Category: Deploy
                Owner: AWS
                Provider: CloudFormation
                Version: "1"
              InputArtifacts:
                - Name: BuildOutput
              Configuration:
                ActionMode: CREATE_UPDATE
                StackName: my-app-prod
                TemplatePath: BuildOutput::template.yaml
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
            lines.append(
                f"  - {info.path}: {len(info.stages)} stage(s), "
                f"approval={info.has_approval}, stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
