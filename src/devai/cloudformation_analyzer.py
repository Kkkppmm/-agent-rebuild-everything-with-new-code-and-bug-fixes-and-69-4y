"""CloudFormationAnalyzer — audit AWS CloudFormation templates for security misconfigurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CFN_SUFFIXES = (".yaml", ".yml", ".json", ".template")
CFN_MARKER_PATTERN = re.compile(
    r"AWSTemplateFormatVersion|\"Resources\"\s*:|Resources:\s*\n|"
    r"\"Parameters\"\s*:|Parameters:\s*\n|Transform:\s*AWS::Serverless|"
    r"\"Transform\"\s*:\s*\"AWS::Serverless",
    re.IGNORECASE,
)
AWS_RESOURCE_PATTERN = re.compile(r"AWS::\w+::\w+")
OPEN_SG_PATTERN = re.compile(r"0\.0\.0\.0/0|::/0")
PUBLIC_ACL_PATTERN = re.compile(
    r"(?:AccessControl|CannedACL)\s*:\s*(?:PublicRead|public-read|PublicReadWrite|public-read-write)",
    re.IGNORECASE,
)
PUBLIC_ACCESS_BLOCK_FALSE_PATTERN = re.compile(
    r"BlockPublicAcls\s*:\s*false|IgnorePublicAcls\s*:\s*false|"
    r"BlockPublicPolicy\s*:\s*false|RestrictPublicBuckets\s*:\s*false",
    re.IGNORECASE,
)
ENCRYPTION_DISABLED_PATTERN = re.compile(
    r"(?:SSESpecification|ServerSideEncryptionConfiguration|BucketEncryption)\s*:\s*(?:false|\{\s*\})|"
    r"Encrypted\s*:\s*false|StorageEncrypted\s*:\s*false",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:Password|Secret|ApiKey|AccessKey|PrivateKey|MasterUserPassword|"
    r"SecretString|ClientSecret|AuthToken)\s*:\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
SKIP_SNAPSHOT_PATTERN = re.compile(
    r"(?:SkipFinalSnapshot|skip_final_snapshot)\s*:\s*true",
    re.IGNORECASE,
)
PUBLICLY_ACCESSIBLE_PATTERN = re.compile(
    r"(?:PubliclyAccessible|publicly_accessible)\s*:\s*true",
    re.IGNORECASE,
)
DELETION_POLICY_DELETE_PATTERN = re.compile(
    r"DeletionPolicy\s*:\s*Delete",
    re.IGNORECASE,
)
DELETION_PROTECTION_FALSE_PATTERN = re.compile(
    r"(?:DeletionProtection|EnableTerminationProtection|DisableApiTermination)\s*:\s*false",
    re.IGNORECASE,
)
WILDCARD_IAM_PATTERN = re.compile(
    r"Action\s*:\s*[\"']?\*[\"']?|Resource\s*:\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
NO_ECHO_FALSE_PATTERN = re.compile(
    r"(?:NoEcho|no_echo)\s*:\s*false",
    re.IGNORECASE,
)
SENSITIVE_PARAM_PLAINTEXT_PATTERN = re.compile(
    r"(?:Type\s*:\s*String|\"Type\"\s*:\s*\"String\").*(?:password|secret|token|api[_-]?key|credential)",
    re.IGNORECASE,
)
HTTP_LISTENER_PATTERN = re.compile(
    r"(?:Protocol|protocol)\s*:\s*(?:HTTP|http)(?!S)",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:Image|ImageUri|ContainerImage|ImageId)\s*:\s*[\"'][^\"']*:latest[\"']",
    re.IGNORECASE,
)
UNENCRYPTED_EBS_PATTERN = re.compile(
    r"(?:Encrypted|encrypted)\s*:\s*false",
    re.IGNORECASE,
)
HTTP_SOURCE_PATTERN = re.compile(
    r"(?:TemplateURL|Location|CodeUri|S3Bucket|S3Key)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)


@dataclass
class CloudFormationFinding:
    """A security or best-practice issue in a CloudFormation template."""

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
class CloudFormationInfo:
    """Parsed metadata about a CloudFormation template."""

    path: str
    resources: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CloudFormationStats:
    """Aggregate CloudFormation analysis statistics."""

    templates: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cloudformation_file(path: Path) -> bool:
    if path.suffix.lower() not in CFN_SUFFIXES:
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(CFN_MARKER_PATTERN.search(text) or AWS_RESOURCE_PATTERN.search(text))


class CloudFormationAnalyzer:
    """Audit AWS CloudFormation templates for hardcoded secrets, open security groups, and risky configs.

    Scans YAML/JSON CloudFormation and SAM templates for plaintext credentials, public S3/RDS
    access, wildcard IAM policies, disabled encryption, and missing NoEcho on sensitive parameters.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[CloudFormationFinding] | None = None
        self._stats: CloudFormationStats | None = None
        self._infos: list[CloudFormationInfo] | None = None

    def templates(self) -> list[Path]:
        """Return CloudFormation template paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cloudformation_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CloudFormationFinding], CloudFormationInfo]:
        findings: list[CloudFormationFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CloudFormationInfo(path=rel)

        info = CloudFormationInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            resource_match = re.search(
                r"^\s*(\w[\w-]*)\s*:\s*\n?\s*Type:\s*(AWS::\S+)",
                line,
                re.IGNORECASE,
            )
            if resource_match:
                info.resources.append(resource_match.group(1))

            aws_type_match = AWS_RESOURCE_PATTERN.search(line)
            if aws_type_match and "Type:" in line:
                resource_type = aws_type_match.group(0)
                if resource_type not in info.resources:
                    info.resources.append(resource_type)

            param_match = re.search(r"^\s*(\w[\w-]*)\s*:", line)
            if param_match and lineno > 1:
                prev = raw_lines[lineno - 2].strip() if lineno >= 2 else ""
                if prev.rstrip(":").endswith("Parameters"):
                    param = param_match.group(1)
                    if param not in info.parameters:
                        info.parameters.append(param)

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use IAM roles or Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in template — use NoEcho parameters or Secrets Manager",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if OPEN_SG_PATTERN.search(line) and (
                "CidrIp" in line
                or "CidrIpv6" in line
                or "SecurityGroupIngress" in line
                or "SecurityGroupEgress" in line
                or "FromPort" in line
            ):
                findings.append(
                    CloudFormationFinding(
                        kind="open_security_group",
                        severity="high",
                        message="security group allows 0.0.0.0/0 — restrict to specific CIDR ranges",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PUBLIC_ACL_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="public_s3_acl",
                        severity="high",
                        message="S3 bucket ACL allows public access — use BlockPublicAccess instead",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PUBLIC_ACCESS_BLOCK_FALSE_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="public_access_block_disabled",
                        severity="high",
                        message="S3 public access block is disabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ENCRYPTION_DISABLED_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="encryption_disabled",
                        severity="high",
                        message="encryption disabled on storage resource — enable SSE/KMS",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PUBLICLY_ACCESSIBLE_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="public_database",
                        severity="high",
                        message="database is publicly accessible — restrict to private subnets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_SNAPSHOT_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="skip_final_snapshot",
                        severity="medium",
                        message="SkipFinalSnapshot enabled — enable final snapshots for data recovery",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DELETION_POLICY_DELETE_PATTERN.search(line) and (
                "AWS::RDS" in "\n".join(raw_lines[max(0, lineno - 5):lineno])
                or "AWS::DynamoDB" in "\n".join(raw_lines[max(0, lineno - 5):lineno])
            ):
                findings.append(
                    CloudFormationFinding(
                        kind="deletion_policy_delete",
                        severity="medium",
                        message="DeletionPolicy: Delete on data resource — use Retain for production",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DELETION_PROTECTION_FALSE_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="deletion_protection_disabled",
                        severity="medium",
                        message="deletion/termination protection disabled — enable on production resources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_IAM_PATTERN.search(line) and (
                "PolicyDocument" in "\n".join(raw_lines[max(0, lineno - 8):lineno + 1])
                or "AWS::IAM" in "\n".join(raw_lines[max(0, lineno - 8):lineno + 1])
            ):
                findings.append(
                    CloudFormationFinding(
                        kind="wildcard_iam",
                        severity="high",
                        message="IAM policy uses wildcard Action or Resource — apply least privilege",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if NO_ECHO_FALSE_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="no_echo_disabled",
                        severity="high",
                        message="NoEcho: false on parameter — set NoEcho: true for sensitive values",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PARAM_PLAINTEXT_PATTERN.search(line) and "NoEcho" not in line:
                findings.append(
                    CloudFormationFinding(
                        kind="sensitive_param_plaintext",
                        severity="medium",
                        message="sensitive parameter without NoEcho — add NoEcho: true",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HTTP_LISTENER_PATTERN.search(line) and (
                "Listener" in line or "LoadBalancer" in line or "AWS::ElasticLoadBalancing" in line
            ):
                findings.append(
                    CloudFormationFinding(
                        kind="http_listener",
                        severity="low",
                        message="HTTP listener without TLS — prefer HTTPS with redirect",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="container/AMI uses :latest tag — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNENCRYPTED_EBS_PATTERN.search(line) and (
                "Volume" in line or "EBS" in line or "BlockDeviceMapping" in line
            ):
                findings.append(
                    CloudFormationFinding(
                        kind="unencrypted_ebs",
                        severity="high",
                        message="EBS volume encryption disabled — set Encrypted: true",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HTTP_SOURCE_PATTERN.search(line):
                findings.append(
                    CloudFormationFinding(
                        kind="insecure_http_source",
                        severity="medium",
                        message="template or artifact fetched over HTTP — use HTTPS S3 URLs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[CloudFormationFinding]:
        """Scan CloudFormation templates and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CloudFormationFinding] = []
        infos: list[CloudFormationInfo] = []
        paths = self.templates()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = CloudFormationStats(
            templates=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CloudFormationStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CloudFormationInfo]:
        """Return parsed template metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no templates)."""
        self.analyze()
        stats = self.stats
        if stats.templates == 0:
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
        """Scaffold a hardened CloudFormation S3 bucket template."""
        return """\
AWSTemplateFormatVersion: '2010-09-09'
Description: Hardened S3 bucket template generated by DevAI

Parameters:
  BucketName:
    Type: String
    Description: Globally unique bucket name

Resources:
  AppBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      BucketName: !Ref BucketName
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256

Outputs:
  BucketArn:
    Value: !GetAtt AppBucket.Arn
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.templates == 0:
            return "CloudFormation templates: none found"
        return (
            f"CloudFormation templates: {stats.templates} template(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "CloudFormation analysis:",
            f"  templates: {stats.templates}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.resources)} resource(s), "
                f"{len(info.parameters)} parameter(s)"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
