"""TerraformAnalyzer — audit Terraform files for security and infrastructure best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

OPEN_SG_PATTERN = re.compile(
    r"(0\.0\.0\.0/0|::/0)",
    re.IGNORECASE,
)
PUBLIC_ACL_PATTERN = re.compile(
    r"acl\s*=\s*[\"']public",
    re.IGNORECASE,
)
ENCRYPTED_FALSE_PATTERN = re.compile(
    r"encrypted\s*=\s*false\b",
    re.IGNORECASE,
)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|access_key|private_key)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
SKIP_FINAL_SNAPSHOT_PATTERN = re.compile(
    r"skip_final_snapshot\s*=\s*true\b",
    re.IGNORECASE,
)
PUBLIC_ACCESS_PATTERN = re.compile(
    r"(block_public_access|publicly_accessible)\s*=\s*false\b",
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
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


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
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_terraform_file(path: Path) -> bool:
    return path.suffix.lower() == ".tf"


class TerraformAnalyzer:
    """Audit Terraform files for security risks and infrastructure best practices.

    Scans for open security groups, public S3 ACLs, disabled encryption,
    hardcoded secrets, public database access, and missing final snapshots.
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
        in_security_group = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("resource "):
                parts = line.split('"')
                if len(parts) >= 3:
                    info.resources.append(f"{parts[1]}.{parts[3]}")

            if line.startswith("provider "):
                parts = line.split('"')
                if len(parts) >= 2:
                    info.providers.append(parts[1])

            if "security_group" in line and line.startswith("resource"):
                in_security_group = True
            elif line.startswith("resource ") and in_security_group:
                in_security_group = False
            elif line == "}" and in_security_group:
                in_security_group = False

            if in_security_group and OPEN_SG_PATTERN.search(line):
                if "cidr" in line.lower() or "ip_range" in line.lower():
                    findings.append(
                        TerraformFinding(
                            kind="open_security_group",
                            severity="high",
                            message="security group allows traffic from anywhere (0.0.0.0/0)",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if PUBLIC_ACL_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="public_acl",
                        severity="high",
                        message="public ACL on storage resource",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ENCRYPTED_FALSE_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="encryption_disabled",
                        severity="high",
                        message="encryption explicitly disabled",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Terraform — use variables and secrets manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_FINAL_SNAPSHOT_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="skip_final_snapshot",
                        severity="medium",
                        message="skip_final_snapshot: true prevents recovery on destroy",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLIC_ACCESS_PATTERN.search(line):
                findings.append(
                    TerraformFinding(
                        kind="public_access",
                        severity="high",
                        message="resource allows public access",
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
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = TerraformStats(
            files=len(paths),
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

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
            return "Terraform files: none found"
        return (
            f"Terraform files: {stats.files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Terraform analysis:",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.resources)} resource(s), "
                f"{len(info.providers)} provider(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
