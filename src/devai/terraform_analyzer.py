"""TerraformAnalyzer — audit Terraform files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TF_EXTENSIONS = (".tf", ".tfvars")
TF_DIR_NAMES = ("terraform", "infra", "infrastructure", "iac", "deploy")

OPEN_CIDR_PATTERN = re.compile(
    r"(cidr_blocks|ipv4_cidr_blocks|cidr_block)\s*=\s*\[[^\]]*0\.0\.0\.0/0",
    re.IGNORECASE,
)
PUBLIC_ACL_PATTERN = re.compile(
    r"acl\s*=\s*['\"]public-(?:read|read-write)['\"]",
    re.IGNORECASE,
)
PUBLIC_ACCESS_PATTERN = re.compile(
    r"block_public_(?:acls|policy)\s*=\s*false",
    re.IGNORECASE,
)
ENCRYPT_FALSE_PATTERN = re.compile(
    r"(encrypt|encrypted|storage_encrypted|server_side_encryption)\s*=\s*false",
    re.IGNORECASE,
)
SKIP_SNAPSHOT_PATTERN = re.compile(
    r"skip_final_snapshot\s*=\s*true",
    re.IGNORECASE,
)
FORCE_DESTROY_PATTERN = re.compile(
    r"force_destroy\s*=\s*true",
    re.IGNORECASE,
)
WILDCARD_IAM_ACTION_PATTERN = re.compile(
    r"Action\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)
WILDCARD_IAM_RESOURCE_PATTERN = re.compile(
    r"Resource\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)
SECRET_ASSIGN_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|\btoken\b|credential|private[_-]?key)\s*=\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
AWS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
INSECURE_HTTP_PATTERN = re.compile(
    r"(endpoint|url|host)\s*=\s*['\"]http://[^'\"]+['\"]",
    re.IGNORECASE,
)
UNPINNED_MODULE_PATTERN = re.compile(
    r'source\s*=\s*["\']git::https?://[^"\']+["\']',
    re.IGNORECASE,
)
UNPINNED_PROVIDER_PATTERN = re.compile(
    r'version\s*=\s*["\']~>?\s*0["\']',
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

    files: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_terraform_file(path: Path) -> bool:
    if path.suffix.lower() not in TF_EXTENSIONS:
        return False
    if any(part in path.parts for part in TF_DIR_NAMES):
        return True
    name_lower = path.name.lower()
    return any(
        marker in name_lower
        for marker in ("main", "variables", "outputs", "providers", "backend", "terraform")
    )


class TerraformAnalyzer:
    """Audit Terraform files for security risks and infrastructure best practices.

    Scans for open security groups (0.0.0.0/0), public S3 ACLs, disabled encryption,
    hardcoded secrets, overly permissive IAM policies, skip_final_snapshot, and
    unpinned module sources.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TerraformFinding] | None = None
        self._stats: TerraformStats | None = None
        self._infos: list[TerraformInfo] | None = None

    def files(self) -> list[Path]:
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
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, TerraformInfo(path=rel)

        info = TerraformInfo(path=rel, lines=len(raw_lines))
        current_resource = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            resource_match = re.match(
                r'resource\s+"([^"]+)"\s+"([^"]+)"',
                line,
            )
            if resource_match:
                current_resource = f"{resource_match.group(1)}.{resource_match.group(2)}"
                info.resources.append(current_resource)
                continue

            provider_match = re.match(r'provider\s+"([^"]+)"', line)
            if provider_match:
                provider = provider_match.group(1)
                if provider not in info.providers:
                    info.providers.append(provider)

            def add_finding(
                kind: str,
                severity: str,
                message: str,
            ) -> None:
                findings.append(
                    TerraformFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if OPEN_CIDR_PATTERN.search(line):
                add_finding(
                    "open_security_group",
                    "high",
                    "ingress allows 0.0.0.0/0 — restrict to known CIDR ranges",
                )

            if PUBLIC_ACL_PATTERN.search(line):
                add_finding(
                    "public_s3_acl",
                    "high",
                    "S3 ACL set to public — use private ACL with bucket policies",
                )

            if PUBLIC_ACCESS_PATTERN.search(line):
                add_finding(
                    "public_access_enabled",
                    "high",
                    "S3 public access block disabled — enable block_public_acls and block_public_policy",
                )

            if ENCRYPT_FALSE_PATTERN.search(line):
                add_finding(
                    "encryption_disabled",
                    "high",
                    "encryption explicitly disabled — enable at-rest encryption",
                )

            if SKIP_SNAPSHOT_PATTERN.search(line):
                add_finding(
                    "skip_final_snapshot",
                    "medium",
                    "skip_final_snapshot = true — final snapshot will not be created on destroy",
                )

            if FORCE_DESTROY_PATTERN.search(line):
                add_finding(
                    "force_destroy",
                    "medium",
                    "force_destroy = true — allows destructive teardown of protected resources",
                )

            if WILDCARD_IAM_ACTION_PATTERN.search(line):
                add_finding(
                    "wildcard_iam_action",
                    "high",
                    "IAM policy Action = \"*\" — use least-privilege actions",
                )

            if WILDCARD_IAM_RESOURCE_PATTERN.search(line):
                add_finding(
                    "wildcard_iam_resource",
                    "high",
                    "IAM policy Resource = \"*\" — scope to specific ARNs",
                )

            if SECRET_ASSIGN_PATTERN.search(line):
                add_finding(
                    "hardcoded_secret",
                    "critical",
                    "possible hardcoded secret in Terraform configuration",
                )

            if AWS_KEY_PATTERN.search(line):
                add_finding(
                    "hardcoded_aws_key",
                    "critical",
                    "hardcoded AWS access key — use IAM roles or secrets manager",
                )

            if INSECURE_HTTP_PATTERN.search(line):
                add_finding(
                    "insecure_http_endpoint",
                    "medium",
                    "HTTP endpoint without TLS — use HTTPS",
                )

            if UNPINNED_MODULE_PATTERN.search(line) and "ref=" not in line:
                add_finding(
                    "unpinned_module",
                    "low",
                    "module source without ref= pin — pin to a tag or commit SHA",
                )

            if UNPINNED_PROVIDER_PATTERN.search(line):
                add_finding(
                    "unpinned_provider",
                    "low",
                    "provider version ~> 0 — pin to a stable major version",
                )

        return findings, info

    def analyze(self) -> list[TerraformFinding]:
        """Scan Terraform files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TerraformFinding] = []
        infos: list[TerraformInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_resources = sum(len(i.resources) for i in infos)
        high = sum(1 for f in findings if f.severity in ("high", "critical"))
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = TerraformStats(
            files=len(paths),
            findings=len(findings),
            resources=total_resources,
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
        """Return parsed file metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no files)."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
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
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_s3_bucket" "app_data" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_acl" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket                  = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        stats = self.stats
        if stats.files == 0:
            return "Terraform files: none found"
        return (
            f"Terraform: {stats.files} file(s), "
            f"{stats.resources} resource(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low) — health {self.health_score():.0f}/100"
        )

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Terraform analysis:",
            f"  files: {stats.files}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health_score: {self.health_score():.0f}/100",
            "",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        return "\n".join(lines)
