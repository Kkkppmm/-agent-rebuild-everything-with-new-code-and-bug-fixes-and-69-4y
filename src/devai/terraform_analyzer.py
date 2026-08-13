"""TerraformAnalyzer — audit Terraform files for security misconfigurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TF_SUFFIXES = (".tf", ".tfvars")

OPEN_SG_PATTERN = re.compile(r"0\.0\.0\.0/0|::/0")
PUBLIC_ACL_PATTERN = re.compile(
    r'acl\s*=\s*"(public-read|public-read-write|authenticated-read)"',
    re.IGNORECASE,
)
PUBLIC_ACCESS_PATTERN = re.compile(
    r"block_public_acls\s*=\s*false|ignore_public_acls\s*=\s*false",
    re.IGNORECASE,
)
ENCRYPTION_DISABLED_PATTERN = re.compile(
    r"encrypt\s*=\s*false|server_side_encryption\s*\{\s*\}",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r'(password|secret|api_key|access_key|private_key)\s*=\s*"[^"]{8,}"',
    re.IGNORECASE,
)
SKIP_SNAPSHOT_PATTERN = re.compile(r"skip_final_snapshot\s*=\s*true\b", re.IGNORECASE)
HTTP_LISTENER_PATTERN = re.compile(
    r"protocol\s*=\s*\"HTTP\"|from_port\s*=\s*80\b",
    re.IGNORECASE,
)


@dataclass
class TerraformFinding:
    """A security issue in a Terraform file."""

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
class TerraformInfo:
    """Parsed metadata about a Terraform file."""

    path: str
    resources: list[str] = field(default_factory=list)
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
    """Audit Terraform files for open security groups, public S3 ACLs, and hardcoded secrets.

    Scans .tf and .tfvars files for overly permissive network rules, disabled
    encryption, public bucket ACLs, and credentials in source.
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
            if not path.is_file():
                continue
            if _is_terraform_file(path):
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

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            if line.startswith("resource "):
                resource = line.split('"')[1] if '"' in line else line
                info.resources.append(resource)

            if OPEN_SG_PATTERN.search(line) and (
                "cidr" in line.lower()
                or "ingress" in line.lower()
                or "egress" in line.lower()
                or "security_group" in line.lower()
            ):
                findings.append(
                    TerraformFinding(
                        kind="open_security_group",
                        severity="high",
                        message="security group allows traffic from 0.0.0.0/0",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLIC_ACL_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="public_s3_acl",
                        severity="high",
                        message="S3 bucket ACL allows public access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLIC_ACCESS_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="public_access_block_disabled",
                        severity="high",
                        message="S3 public access block is disabled",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ENCRYPTION_DISABLED_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="encryption_disabled",
                        severity="high",
                        message="encryption is disabled for a storage resource",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="hardcoded_secret",
                        severity="critical",
                        message="hardcoded secret in Terraform — use variables and secret manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_SNAPSHOT_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="skip_final_snapshot",
                        severity="medium",
                        message="skip_final_snapshot = true prevents final RDS backup",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HTTP_LISTENER_PATTERN.search(line) and "redirect" not in line.lower():
                if "listener" in line.lower() or "load_balancer" in line.lower():
                    findings.append(
                        TerraformFinding(
                            kind="http_listener",
                            severity="low",
                            message="HTTP listener without TLS — prefer HTTPS",
                            path=rel,
                            lineno=lineno,
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
        high = sum(1 for f in findings if f.severity in ("high", "critical"))
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
      sse_algorithm = "AES256"
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
        stats = self.stats
        lines = [
            "Terraform analysis:",
            f"  terraform files: {stats.terraform_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.resources)} resource(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
