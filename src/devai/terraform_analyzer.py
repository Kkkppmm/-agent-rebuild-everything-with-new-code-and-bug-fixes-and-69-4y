"""TerraformAnalyzer — audit Terraform files for security and infrastructure best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TF_SUFFIXES = (".tf", ".tfvars")

OPEN_SG_PATTERN = re.compile(
    r"cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0",
    re.IGNORECASE,
)
PUBLIC_S3_ACL_PATTERN = re.compile(
    r'acl\s*=\s*"(public-read|public-read-write|authenticated-read)"',
    re.IGNORECASE,
)
DISABLED_ENCRYPTION_PATTERN = re.compile(
    r"(encrypt\w*\s*=\s*false|server_side_encryption\s*\{[^}]*enabled\s*=\s*false)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|access_key|secret_key)\s*=\s*\"[^$\"][^\"]*\"",
    re.IGNORECASE,
)
SKIP_FINAL_SNAPSHOT_PATTERN = re.compile(
    r"skip_final_snapshot\s*=\s*true",
    re.IGNORECASE,
)
WILDCARD_IAM_PATTERN = re.compile(
    r'Action\s*=\s*"\*"',
    re.IGNORECASE,
)
WILDCARD_RESOURCE_PATTERN = re.compile(
    r'Resource\s*=\s*"\*"',
    re.IGNORECASE,
)
PUBLIC_ACCESS_BLOCK_OFF_PATTERN = re.compile(
    r"block_public_acls\s*=\s*false",
    re.IGNORECASE,
)
HTTP_LISTENER_PATTERN = re.compile(
    r"protocol\s*=\s*\"HTTP\"",
    re.IGNORECASE,
)
UNENCRYPTED_EBS_PATTERN = re.compile(
    r"encrypted\s*=\s*false",
    re.IGNORECASE,
)
TF_VERSION_UNPINNED_PATTERN = re.compile(
    r'required_version\s*=\s*">=',
    re.IGNORECASE,
)


@dataclass
class TerraformFinding:
    """A security or best-practice issue in a Terraform file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    resource: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        res = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{res} — {self.message}"


@dataclass
class TerraformInfo:
    """Parsed metadata about a Terraform file."""

    path: str
    resources: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TerraformStats:
    """Aggregate Terraform analysis statistics."""

    terraform_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_terraform_file(path: Path) -> bool:
    return path.suffix.lower() in TF_SUFFIXES


class TerraformAnalyzer:
    """Audit Terraform files for security risks and infrastructure best practices.

    Scans for open security groups (0.0.0.0/0), public S3 ACLs, disabled encryption,
    hardcoded secrets, overly permissive IAM policies, and unencrypted storage.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TerraformFinding] | None = None
        self._stats: TerraformStats | None = None
        self._infos: list[TerraformInfo] | None = None

    def terraform_files(self) -> list[Path]:
        """Return Terraform file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_terraform_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TerraformFinding], TerraformInfo]:
        findings: list[TerraformFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TerraformInfo(path=rel)

        info = TerraformInfo(path=rel, lines=len(raw_lines))
        current_resource = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.split("#", 1)[0].rstrip() if "#" in raw else raw.rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            resource_match = re.match(r'resource\s+"([^"]+)"\s+"([^"]+)"', stripped)
            if resource_match:
                current_resource = f"{resource_match.group(1)}.{resource_match.group(2)}"
                info.resources.append(current_resource)

            provider_match = re.match(r'provider\s+"([^"]+)"', stripped)
            if provider_match:
                info.providers.append(provider_match.group(1))

            checks = [
                (OPEN_SG_PATTERN, "open_security_group", "high", "security group allows 0.0.0.0/0 ingress"),
                (PUBLIC_S3_ACL_PATTERN, "public_s3_acl", "high", "S3 bucket has a public ACL"),
                (DISABLED_ENCRYPTION_PATTERN, "disabled_encryption", "high", "encryption is explicitly disabled"),
                (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Terraform — use variables and secret managers"),
                (SKIP_FINAL_SNAPSHOT_PATTERN, "skip_final_snapshot", "medium", "skip_final_snapshot = true risks data loss on destroy"),
                (WILDCARD_IAM_PATTERN, "wildcard_iam_action", "high", 'IAM policy Action = "*" is overly permissive'),
                (WILDCARD_RESOURCE_PATTERN, "wildcard_iam_resource", "medium", 'IAM policy Resource = "*" grants broad access'),
                (PUBLIC_ACCESS_BLOCK_OFF_PATTERN, "public_access_block_off", "high", "block_public_acls = false allows public bucket access"),
                (HTTP_LISTENER_PATTERN, "http_listener", "medium", "load balancer listener uses HTTP instead of HTTPS"),
                (UNENCRYPTED_EBS_PATTERN, "unencrypted_ebs", "high", "EBS volume encryption is disabled"),
                (TF_VERSION_UNPINNED_PATTERN, "unpinned_tf_version", "low", "required_version uses >= instead of pinning an exact version"),
            ]

            for pattern, kind, severity, message in checks:
                if pattern.search(line):
                    findings.append(
                        TerraformFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

        return findings, info

    def analyze(self) -> list[TerraformFinding]:
        """Scan Terraform files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TerraformFinding] = []
        infos: list[TerraformInfo] = []
        paths = self.terraform_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = TerraformStats(
            terraform_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TerraformStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TerraformInfo]:
        """Return parsed Terraform metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no Terraform files)."""
        self.analyze()
        stats = self.stats
        if stats.terraform_files == 0:
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
        """Scaffold a hardened Terraform S3 bucket template."""
        return """\
# Generated by DevAI TerraformAnalyzer
terraform {
  required_version = "1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.70.0"
    }
  }
}

resource "aws_s3_bucket" "app" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app" {
  bucket = aws_s3_bucket.app.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.terraform_files == 0:
            return "Terraform files: none found"
        return (
            f"Terraform files: {stats.terraform_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        lines = [
            "Terraform analysis:",
            self.summary(),
            f"Health score: {self.health_score()}/100",
        ]
        if self._findings:
            lines.append("")
            lines.append("Findings:")
            for finding in self._findings[:50]:
                lines.append(f"  - {finding.format()}")
            if len(self._findings) > 50:
                lines.append(f"  ... and {len(self._findings) - 50} more")
        return "\n".join(lines)
