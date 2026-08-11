"""AWSCodeBuildAnalyzer — audit AWS CodeBuild buildspec files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUILDSPEC_FILENAMES = (
    "buildspec.yml",
    "buildspec.yaml",
    "buildspec.json",
)
BUILDSPEC_DIRS = (".aws", "aws", "ci/aws", "codebuild", ".codebuild")

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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r":latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:--privileged|privileged\s*:\s*true)",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?(?:CODEBUILD_[A-Z0-9_]+|AWS_[A-Z0-9_]+|BRANCH|COMMIT|TAG)\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"[\"']?AKIA[0-9A-Z]{16}[\"']?",
    re.IGNORECASE,
)
UNENCRYPTED_ARTIFACTS_PATTERN = re.compile(
    r"^\s*encryption\s*:\s*false\s*$",
    re.IGNORECASE,
)
PUBLIC_S3_ACL_PATTERN = re.compile(
    r"(?:public-read|public-read-write|authenticated-read|bucket-owner-full-control)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:--user\s+root|run-as-user\s*:\s*root|USER\s+root)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
PLAINTEXT_SECRETS_MANAGER_PATTERN = re.compile(
    r"^\s*secrets-manager\s*:\s*\n\s+[A-Z0-9_]+\s*:\s*[\"'][^\"']+[\"']",
    re.IGNORECASE | re.MULTILINE,
)
INSECURE_DOCKER_RUN_PATTERN = re.compile(
    r"docker\s+run\b[^;\n]*(?:--cap-add|--network\s+host|--pid\s+host)",
    re.IGNORECASE,
)
UNPINNED_RUNTIME_PATTERN = re.compile(
    r"^\s*(?:python|node|ruby|golang|java|dotnet|php)\s*:\s*(?:latest|\*)\s*$",
    re.IGNORECASE,
)


@dataclass
class AWSCodeBuildFinding:
    """A security or best-practice issue in an AWS CodeBuild buildspec."""

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
class AWSCodeBuildInfo:
    """Parsed metadata about a buildspec file."""

    path: str
    phases: list[str] = field(default_factory=list)
    runtime_versions: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class AWSCodeBuildStats:
    """Aggregate AWS CodeBuild analysis statistics."""

    buildspecs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_buildspec_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in BUILDSPEC_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(BUILDSPEC_DIRS) and lower.endswith((".yml", ".yaml", ".json")):
        return True
    return False


class AWSCodeBuildAnalyzer:
    """Audit AWS CodeBuild buildspec files for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `buildspec.yml` for curl-pipe-to-shell, privileged Docker, unencrypted artifacts,
    plaintext AWS keys, and CODEBUILD_* variable injection in commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AWSCodeBuildFinding] | None = None
        self._stats: AWSCodeBuildStats | None = None
        self._infos: list[AWSCodeBuildInfo] | None = None

    def files(self) -> list[Path]:
        """Return buildspec files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_buildspec_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AWSCodeBuildFinding], AWSCodeBuildInfo]:
        findings: list[AWSCodeBuildFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AWSCodeBuildInfo(path=rel)

        info = AWSCodeBuildInfo(path=rel, lines=len(raw_lines))
        in_security_phase = False
        in_env_variables = False
        current_phase = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            phase_match = re.match(r"^\s*(install|pre_build|build|post_build)\s*:", line, re.IGNORECASE)
            if phase_match:
                current_phase = phase_match.group(1).lower()
                info.phases.append(current_phase)
                in_security_phase = bool(SECURITY_STEP_PATTERN.search(current_phase))
                in_env_variables = False
                continue

            if re.match(r"^\s*env\s*:", line, re.IGNORECASE):
                in_env_variables = True
                continue

            if re.match(r"^\s*(phases|artifacts|cache|reports)\s*:", line, re.IGNORECASE):
                in_env_variables = False

            if re.match(r"^\s*variables\s*:", line, re.IGNORECASE):
                in_env_variables = True
                continue

            if re.match(r"^\s*(parameter-store|secrets-manager|exported-variables)\s*:", line, re.IGNORECASE):
                in_env_variables = False

            runtime_match = re.match(
                r"^\s*(python|node|ruby|golang|java|dotnet|php)\s*:\s*(.+)$",
                line,
                re.IGNORECASE,
            )
            if runtime_match:
                info.runtime_versions.append(f"{runtime_match.group(1)}:{runtime_match.group(2).strip()}")

            if in_env_variables and HARDCODED_ENV_VALUE_PATTERN.match(line):
                if not re.search(r"(?:true|false|null|\$\{)", line, re.IGNORECASE):
                    findings.append(
                        AWSCodeBuildFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded value in env variables — use parameter-store or secrets-manager",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
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
                    AWSCodeBuildFinding(
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
                    AWSCodeBuildFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_DOCKER_RUN_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="insecure_docker_run",
                        severity="high",
                        message="docker run with elevated capabilities or host networking — restrict privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and re.search(r"^\s*-\s", raw):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="script_injection",
                        severity="medium",
                        message="CODEBUILD_* variable interpolated in command — validate untrusted inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNENCRYPTED_ARTIFACTS_PATTERN.match(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="unencrypted_artifacts",
                        severity="medium",
                        message="artifacts encryption disabled — enable S3 encryption for build outputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLIC_S3_ACL_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="public_s3_acl",
                        severity="high",
                        message="overly permissive S3 ACL — restrict artifact bucket access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="root_user",
                        severity="medium",
                        message="build runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in buildspec — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_RUNTIME_PATTERN.match(line):
                findings.append(
                    AWSCodeBuildFinding(
                        kind="unpinned_runtime",
                        severity="medium",
                        message="runtime version unpinned — specify an exact version for reproducible builds",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_phase and re.search(r"on-failure\s*:\s*(?:ABORT|CONTINUE)", line, re.IGNORECASE):
                if re.search(r"CONTINUE", line, re.IGNORECASE):
                    findings.append(
                        AWSCodeBuildFinding(
                            kind="security_failure_ignored",
                            severity="medium",
                            message="security phase continues on failure — failing scans should block builds",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        content = "\n".join(raw_lines)
        if PLAINTEXT_SECRETS_MANAGER_PATTERN.search(content):
            findings.append(
                AWSCodeBuildFinding(
                    kind="plaintext_secrets_manager",
                    severity="high",
                    message="plaintext value in secrets-manager block — reference ARN or name only",
                    path=rel,
                    lineno=1,
                    line="secrets-manager",
                )
            )

        return findings, info

    def analyze(self) -> list[AWSCodeBuildFinding]:
        """Scan buildspec files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AWSCodeBuildFinding] = []
        infos: list[AWSCodeBuildInfo] = []
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
        self._stats = AWSCodeBuildStats(
            buildspecs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AWSCodeBuildStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AWSCodeBuildInfo]:
        """Return parsed buildspec metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no buildspecs)."""
        self.analyze()
        stats = self.stats
        if stats.buildspecs == 0:
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
        """Scaffold a hardened AWS CodeBuild buildspec template."""
        return """\
# Generated by DevAI AWSCodeBuildAnalyzer
version: 0.2

env:
  variables:
    PYTHON_VERSION: "3.12"
  parameter-store:
    API_ENDPOINT: /prod/api-endpoint
  secrets-manager:
    DB_PASSWORD: arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install -r requirements.txt

  pre_build:
    commands:
      - python -m pytest

  build:
    commands:
      - python -m build

  post_build:
    commands:
      - echo Build completed on $CODEBUILD_BUILD_ID

artifacts:
  files:
    - dist/**/*
  encryption: true

cache:
  paths:
    - /root/.cache/pip/**/*
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.buildspecs == 0:
            return "AWS CodeBuild: none found"
        return (
            f"AWS CodeBuild: {stats.buildspecs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "AWS CodeBuild buildspec analysis:",
            f"  buildspecs: {stats.buildspecs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            phases = ", ".join(info.phases[:5]) or "none"
            lines.append(f"  - {info.path}: phases=[{phases}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
