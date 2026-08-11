"""AWSCodePipelineAnalyzer — audit AWS CodePipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPELINE_FILENAMES = (
    "pipeline.json",
    "pipeline.yaml",
    "pipeline.yml",
    "codepipeline.json",
    "codepipeline.yaml",
    "codepipeline.yml",
)
PIPELINE_DIRS = (".aws", "aws", "ci/aws", "codepipeline", ".codepipeline")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|oauth[_-]?token|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_CONFIG_VALUE_PATTERN = re.compile(
    r"^\s*(?:OAuthToken|GitHubToken|GitHubOAuthToken|Token|SecretString|AccessKey|SecretAccessKey)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"[\"']?AKIA[0-9A-Z]{16}[\"']?",
    re.IGNORECASE,
)
ADMIN_IAM_PATTERN = re.compile(
    r"(?:AdministratorAccess|\*:\*|\*:\*:\*)",
    re.IGNORECASE,
)
UNENCRYPTED_ARTIFACT_STORE_PATTERN = re.compile(
    r"^\s*ArtifactStore\s*:",
    re.IGNORECASE,
)
ENCRYPTION_KEY_PATTERN = re.compile(
    r"^\s*EncryptionKey\s*:",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"[#${]?\{?(?:CodePipeline|AWS|PIPELINE)_[A-Z0-9_]+\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
PUBLIC_S3_ACL_PATTERN = re.compile(
    r"(?:public-read|public-read-write|authenticated-read)",
    re.IGNORECASE,
)
WILDCARD_BRANCH_PATTERN = re.compile(
    r"^\s*BranchName\s*:\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
UNPINNED_ACTION_VERSION_PATTERN = re.compile(
    r"^\s*Version\s*:\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
CODEPIPELINE_RESOURCE_PATTERN = re.compile(
    r"AWS::CodePipeline::Pipeline",
    re.IGNORECASE,
)
CODEPIPELINE_CONTENT_PATTERN = re.compile(
    r"(?:CodePipeline::Pipeline|\"pipeline\"\s*:|^\s*stages\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
MANUAL_APPROVAL_PATTERN = re.compile(
    r"^\s*Provider\s*:\s*[\"']?Manual[\"']?",
    re.IGNORECASE,
)
DEPLOY_STAGE_PATTERN = re.compile(
    r"^\s*-?\s*Name\s*:\s*[\"']?(?:Deploy|Production|Release|Prod)[\"']?",
    re.IGNORECASE,
)
INSECURE_S3_LOCATION_PATTERN = re.compile(
    r"^\s*Location\s*:\s*[\"']?[^\"'\n]*\.s3\.amazonaws\.com",
    re.IGNORECASE,
)
CROSS_ACCOUNT_ROLE_PATTERN = re.compile(
    r"arn:aws:iam::\d{12}:role/[^\"'\n]*(?:Admin|PowerUser|FullAccess)",
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
    actions: list[str] = field(default_factory=list)
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
    if "pipeline" in lower and lower.endswith((".yml", ".yaml", ".json")):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(PIPELINE_DIRS) and lower.endswith((".yml", ".yaml", ".json")):
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        CODEPIPELINE_RESOURCE_PATTERN.search(content)
        or CODEPIPELINE_CONTENT_PATTERN.search(content)
    )


class AWSCodePipelineAnalyzer:
    """Audit AWS CodePipeline configs for hardcoded secrets, weak IAM, and unsafe actions.

    Scans pipeline YAML/JSON and CloudFormation templates for plaintext OAuth tokens,
    unencrypted artifact stores, wildcard branches, and CodePipeline variable injection.
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
        in_artifact_store = False
        has_encryption_key = False
        has_deploy_stage = False
        has_manual_approval = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if MANUAL_APPROVAL_PATTERN.search(line):
                has_manual_approval = True

            stage_match = re.match(r"^\s*-?\s*Name\s*:\s*[\"']?([^\"'\n]+)[\"']?\s*$", line, re.IGNORECASE)
            if stage_match:
                name = stage_match.group(1).strip()
                if name not in info.stages and name not in info.actions:
                    if DEPLOY_STAGE_PATTERN.match(line):
                        has_deploy_stage = True
                        info.stages.append(name)
                    elif re.search(r"ActionTypeId|Provider", "\n".join(raw_lines[lineno:lineno + 3]), re.IGNORECASE):
                        info.actions.append(name)
                    elif re.search(r"Stages\s*:", "\n".join(raw_lines[max(0, lineno - 8):lineno]), re.IGNORECASE):
                        info.stages.append(name)
                        if DEPLOY_STAGE_PATTERN.match(line):
                            has_deploy_stage = True

            if re.match(r"^\s*ArtifactStore\s*:", line, re.IGNORECASE):
                in_artifact_store = True
                has_encryption_key = False
                continue

            if in_artifact_store and ENCRYPTION_KEY_PATTERN.match(line):
                has_encryption_key = True

            if in_artifact_store and re.match(r"^\s*(?:Stages|RoleArn)\s*:", line, re.IGNORECASE):
                if not has_encryption_key:
                    findings.append(
                        AWSCodePipelineFinding(
                            kind="unencrypted_artifacts",
                            severity="medium",
                            message="artifact store without KMS encryption — enable EncryptionKey on ArtifactStore",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                in_artifact_store = False

            if HARDCODED_CONFIG_VALUE_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in pipeline configuration — use Secrets Manager or SSM",
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
                        message="hardcoded secret — use AWS Secrets Manager or SSM Parameter Store",
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

            if ADMIN_IAM_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="admin_iam_role",
                        severity="high",
                        message="overly permissive IAM policy or role — follow least privilege",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CROSS_ACCOUNT_ROLE_PATTERN.search(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="privileged_cross_account_role",
                        severity="high",
                        message="cross-account role with elevated privileges — restrict trust and permissions",
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

            if WILDCARD_BRANCH_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="wildcard_branch",
                        severity="medium",
                        message="wildcard branch source — pin to a specific branch or tag",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_ACTION_VERSION_PATTERN.match(line):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="unpinned_action_version",
                        severity="medium",
                        message="action version unpinned — specify an exact provider version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and re.search(
                r"(?:UserParameters|Configuration|commands|script)", line, re.IGNORECASE
            ):
                findings.append(
                    AWSCodePipelineFinding(
                        kind="script_injection",
                        severity="medium",
                        message="CodePipeline variable interpolated in action config — validate untrusted inputs",
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
                        message="overly permissive S3 ACL on artifact bucket — restrict bucket access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_S3_LOCATION_PATTERN.match(line) and not has_encryption_key:
                findings.append(
                    AWSCodePipelineFinding(
                        kind="insecure_artifact_location",
                        severity="low",
                        message="S3 artifact location without visible encryption — verify bucket encryption",
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
                        message="insecure HTTP URL in pipeline config — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if in_artifact_store and not has_encryption_key:
            findings.append(
                AWSCodePipelineFinding(
                    kind="unencrypted_artifacts",
                    severity="medium",
                    message="artifact store without KMS encryption — enable EncryptionKey on ArtifactStore",
                    path=rel,
                    lineno=1,
                    line="ArtifactStore",
                )
            )

        if has_deploy_stage and not has_manual_approval:
            findings.append(
                AWSCodePipelineFinding(
                    kind="missing_manual_approval",
                    severity="medium",
                    message="deploy/production stage without manual approval action — add a Manual approval gate",
                    path=rel,
                    lineno=1,
                    line="Stages",
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
        """Scaffold a hardened AWS CodePipeline CloudFormation template."""
        return """\
# Generated by DevAI AWSCodePipelineAnalyzer
AWSTemplateFormatVersion: '2010-09-09'
Description: Hardened AWS CodePipeline with encrypted artifacts and manual approval

Resources:
  PipelineArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms

  PipelineRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: codepipeline.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AWSCodePipeline_FullAccess

  AppPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: app-pipeline
      RoleArn: !GetAtt PipelineRole.Arn
      ArtifactStore:
        Type: S3
        Location: !Ref PipelineArtifactBucket
        EncryptionKey:
          Type: KMS
          Id: alias/aws/s3
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId:
                Category: Source
                Owner: AWS
                Provider: CodeCommit
                Version: '1'
              Configuration:
                RepositoryName: my-repo
                BranchName: main
              OutputArtifacts:
                - Name: SourceOutput
        - Name: Build
          Actions:
            - Name: BuildAction
              ActionTypeId:
                Category: Build
                Owner: AWS
                Provider: CodeBuild
                Version: '1'
              Configuration:
                ProjectName: my-build-project
              InputArtifacts:
                - Name: SourceOutput
              OutputArtifacts:
                - Name: BuildOutput
        - Name: Deploy
          Actions:
            - Name: Approval
              ActionTypeId:
                Category: Approval
                Owner: AWS
                Provider: Manual
                Version: '1'
              Configuration:
                CustomData: Approve production deployment
            - Name: DeployAction
              ActionTypeId:
                Category: Deploy
                Owner: AWS
                Provider: CodeDeploy
                Version: '1'
              Configuration:
                ApplicationName: my-app
                DeploymentGroupName: production
              InputArtifacts:
                - Name: BuildOutput
              RunOrder: 2
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
            "AWS CodePipeline config analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(f"  - {info.path}: stages=[{stages}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
