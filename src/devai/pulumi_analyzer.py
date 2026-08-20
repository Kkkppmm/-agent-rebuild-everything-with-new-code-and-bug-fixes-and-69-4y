"""PulumiAnalyzer — audit Pulumi IaC projects for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PULUMI_PROJECT_FILENAMES = ("Pulumi.yaml", "pulumi.yaml")
PULUMI_STACK_SUFFIX = ".yaml"
PULUMI_SOURCE_SUFFIXES = (".py", ".ts", ".js", ".go")
PULUMI_MARKER_PATTERN = re.compile(
    r"\b(?:import\s+pulumi|from\s+pulumi|@pulumi/|pulumi\.|pulumi_aws|pulumi_kubernetes|"
    r"require\([\"']@pulumi/|pulumi\.Config\()",
    re.IGNORECASE,
)
PULUMI_RESOURCE_PATTERN = re.compile(
    r"\b(?:new\s+\w+\(|pulumi\.(aws|azure|gcp|kubernetes)\.)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key)\s*[:=]\s*[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
PLAINTEXT_CONFIG_PATTERN = re.compile(
    r"[\w-]*(?:password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*:\s*[\"']?[^\s\"'#]+",
    re.IGNORECASE,
)
SECURE_FALSE_PATTERN = re.compile(r"\bsecure\s*:\s*false\b", re.IGNORECASE)
HTTP_BACKEND_PATTERN = re.compile(
    r"(?:url|endpoint|backend)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
FILE_BACKEND_PATTERN = re.compile(
    r"(?:backend|secretsprovider)\s*:\s*[\"']?(?:file|local)://",
    re.IGNORECASE,
)
PUBLIC_ACCESS_PATTERN = re.compile(
    r"(?:publicly_accessible|publiclyAccessible|public_access|publicAccess)\s*[:=]\s*true",
    re.IGNORECASE,
)
OPEN_SG_PATTERN = re.compile(r"0\.0\.0\.0/0|::/0")
SKIP_SNAPSHOT_PATTERN = re.compile(
    r"(?:skip_final_snapshot|skipFinalSnapshot)\s*[:=]\s*true",
    re.IGNORECASE,
)
PROTECT_FALSE_PATTERN = re.compile(
    r"(?:protect|deletion_protection|deletionProtection)\s*[:=]\s*false",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"[\"']?(?:image|container_image|containerImage|ami)[\"']?\s*[:=]\s*[\"'][^\"']*:latest[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
PLAINTEXT_CONFIG_CMD_PATTERN = re.compile(
    r"pulumi\s+config\s+set\s+(?:--plaintext\s+)?(?:\w+:)?(?:password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"^\s*\w+:\s*version:\s*[\"']?(?:latest|\*)[\"']?\s*$",
    re.IGNORECASE,
)
LOG_VERBOSITY_PATTERN = re.compile(
    r"(?:log_verbosity|logVerbosity|pulumi:log_verbosity)\s*[:=]\s*(?:9|10|11)",
    re.IGNORECASE,
)
ENCRYPTION_DISABLED_PATTERN = re.compile(
    r"(?:encrypted|server_side_encryption|serverSideEncryption)\s*[:=]\s*false",
    re.IGNORECASE,
)
PASSPHRASE_IN_CONFIG_PATTERN = re.compile(
    r"(?:passphrase|encryptionSalt|encryptionsalt)\s*:\s*[\"']?[^\s\"'#]+",
    re.IGNORECASE,
)
INSECURE_HTTP_SOURCE_PATTERN = re.compile(
    r'(?:source|url|registry)\s*[:=]\s*["\']http://(?!localhost|127\.0\.0\.1)[^\s"\']+',
    re.IGNORECASE,
)


@dataclass
class PulumiFinding:
    """A security or best-practice issue in a Pulumi project."""

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
class PulumiInfo:
    """Parsed metadata about a Pulumi project file."""

    path: str
    stack: str = ""
    runtime: str = ""
    plugins: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class PulumiStats:
    """Aggregate Pulumi analysis statistics."""

    projects: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pulumi_stack_file(path: Path) -> bool:
    name = path.name
    if name in PULUMI_PROJECT_FILENAMES:
        return True
    if name.startswith("Pulumi.") and name.endswith(PULUMI_STACK_SUFFIX):
        return True
    return False


def _is_pulumi_source_file(path: Path) -> bool:
    if path.suffix.lower() not in PULUMI_SOURCE_SUFFIXES:
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(PULUMI_MARKER_PATTERN.search(text) or PULUMI_RESOURCE_PATTERN.search(text))


def _is_pulumi_file(path: Path) -> bool:
    return _is_pulumi_stack_file(path) or _is_pulumi_source_file(path)


class PulumiAnalyzer:
    """Audit Pulumi IaC projects for hardcoded secrets, insecure backends, and risky configs.

    Scans ``Pulumi.yaml``, stack config files, and Pulumi program source for plaintext
    credentials, HTTP backends, public database access, unprotected resources, and unpinned plugins.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[PulumiFinding] | None = None
        self._stats: PulumiStats | None = None
        self._infos: list[PulumiInfo] | None = None

    def files(self) -> list[Path]:
        """Return Pulumi project and source files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pulumi_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PulumiFinding], PulumiInfo]:
        findings: list[PulumiFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PulumiInfo(path=rel)

        text = "\n".join(raw_lines)
        info = PulumiInfo(path=rel, lines=len(raw_lines))

        if path.name.startswith("Pulumi.") and path.name.endswith(".yaml"):
            info.stack = path.name.removeprefix("Pulumi.").removesuffix(".yaml")

        runtime_match = re.search(r"^\s*runtime:\s*(\S+)", text, re.MULTILINE | re.IGNORECASE)
        if runtime_match:
            info.runtime = runtime_match.group(1).strip("\"'")

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            plugin_match = re.search(r"^\s*(\w[\w-]*):\s*version:", stripped, re.IGNORECASE)
            if plugin_match:
                plugin = plugin_match.group(1)
                if plugin not in info.plugins:
                    info.plugins.append(plugin)

            resource_match = re.search(
                r"(?:new\s+(\w+)\(|pulumi\.(?:aws|azure|gcp|kubernetes)\.(\w+))",
                stripped,
                re.IGNORECASE,
            )
            if resource_match:
                resource = resource_match.group(1) or resource_match.group(2)
                if resource and resource not in info.resources:
                    info.resources.append(resource)

            if AWS_ACCESS_KEY_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="hardcoded_aws_key",
                        severity="high",
                        message="hardcoded AWS access key — use IAM roles or Pulumi secrets",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Pulumi config or source — use pulumi config set --secret",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PLAINTEXT_CONFIG_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="plaintext_stack_secret",
                        severity="high",
                        message="plaintext secret in stack config — use 'pulumi config set --secret'",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PASSPHRASE_IN_CONFIG_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="passphrase_in_config",
                        severity="high",
                        message="encryption passphrase in config file — use PULUMI_CONFIG_PASSPHRASE env var",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SECURE_FALSE_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="secure_disabled",
                        severity="high",
                        message="secure: false in backend config — enable encryption for state and secrets",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if HTTP_BACKEND_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="insecure_http_backend",
                        severity="high",
                        message="HTTP backend URL — use HTTPS with TLS for Pulumi state storage",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if FILE_BACKEND_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="file_backend",
                        severity="medium",
                        message="file:// backend — use cloud-backed state with encryption for team workflows",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PUBLIC_ACCESS_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="public_access",
                        severity="high",
                        message="publicly accessible resource — restrict to private subnets or VPC",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if OPEN_SG_PATTERN.search(stripped) and (
                "cidr" in stripped.lower()
                or "ingress" in stripped.lower()
                or "security" in stripped.lower()
            ):
                findings.append(
                    PulumiFinding(
                        kind="open_security_group",
                        severity="high",
                        message="security group allows 0.0.0.0/0 — restrict to specific CIDR ranges",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if SKIP_SNAPSHOT_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="skip_final_snapshot",
                        severity="medium",
                        message="skip_final_snapshot enabled — enable final snapshots for data recovery",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PROTECT_FALSE_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="protect_disabled",
                        severity="medium",
                        message="protect/deletion_protection disabled — enable on production resources",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if LATEST_TAG_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="container image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if ENCRYPTION_DISABLED_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="encryption_disabled",
                        severity="high",
                        message="encryption disabled on storage resource — enable server-side encryption",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script integrity before execution",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if PLAINTEXT_CONFIG_CMD_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="plaintext_config_command",
                        severity="high",
                        message="pulumi config set without --secret — use --secret for sensitive values",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if UNPINNED_PLUGIN_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="unpinned_plugin",
                        severity="medium",
                        message="plugin version set to latest/* — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if LOG_VERBOSITY_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="verbose_logging",
                        severity="low",
                        message="high log verbosity may expose secrets in CI logs — use level 3 or lower",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

            if INSECURE_HTTP_SOURCE_PATTERN.search(stripped):
                findings.append(
                    PulumiFinding(
                        kind="insecure_http_source",
                        severity="medium",
                        message="module/source fetched over HTTP — use HTTPS or pinned registry URLs",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if path.name in PULUMI_PROJECT_FILENAMES and "backend:" not in text.lower():
            findings.append(
                PulumiFinding(
                    kind="missing_backend",
                    severity="low",
                    message="no backend configured in Pulumi.yaml — configure remote state for team use",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[PulumiFinding]:
        """Scan Pulumi project files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PulumiFinding] = []
        infos: list[PulumiInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        project_files = sum(1 for p in paths if _is_pulumi_stack_file(p))
        self._findings = findings
        self._infos = infos
        self._stats = PulumiStats(
            projects=project_files,
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PulumiStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PulumiInfo]:
        """Return parsed project metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no projects)."""
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
        """Scaffold a hardened Pulumi.yaml template."""
        return """\
# Hardened Pulumi.yaml template
name: my-project
runtime: python
description: Secure Pulumi project template

backend:
  url: s3://my-org-pulumi-state?region=us-east-1&awssdk=v2

config:
  pulumi:tags:
    value:
      environment: production
      managed-by: pulumi

# Use: pulumi config set --secret dbPassword <value>
# Never store secrets in Pulumi.<stack>.yaml without encryption
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.files == 0:
            return "Pulumi: none found"
        return (
            f"Pulumi: {stats.projects} project(s), {stats.files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pulumi project analysis:",
            f"  projects: {stats.projects}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: stack={info.stack or 'n/a'}, "
                f"runtime={info.runtime or 'n/a'}, "
                f"plugins={info.plugins or 'none'}, "
                f"resources={info.resources or 'none'}"
            )
        for finding in self._findings or []:
            lines.append(f"  {finding.format()}")
        return "\n".join(lines)
