"""HarnessCIAnalyzer — audit Harness CI pipeline YAML for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

HARNESS_DIRS = (".harness", "harness", "ci/harness")
HARNESS_PIPELINE_NAMES = ("pipeline.yaml", "pipeline.yml")
HARNESS_SUFFIXES = (".harness.yaml", ".harness.yml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"^\s*value\s*:\s*(?:[\"'][^\"'{}\s][^\"']+[\"']|[A-Za-z0-9_\-]{8,})\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|connectorRef)\s*:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged\s*:\s*true|--privileged\b)",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(
    r"(?:runAsUser\s*:\s*0|runAsUser\s*:\s*[\"']?root[\"']?)",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:<\+(?:pipeline|trigger|input|secrets|serviceConfig)\.[^>]+>|\$\{?HARNESS_[A-Z0-9_]+\}?)",
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
INSECURE_SETTING_PATTERN = re.compile(
    r"^\s*(?:disableAutoAbort|allowStepRunAsUser|skipResourceValidation|insecureRegistries)\s*:\s*true\s*$",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
PLAINTEXT_PIPELINE_VAR_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*[A-Z0-9_]+\s*\n\s+value\s*:\s*(?:[\"'][^\"'{}\s][^\"']+[\"']|[A-Za-z0-9_\-]{8,})\s*$",
    re.IGNORECASE | re.MULTILINE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"(?:networkMode\s*:\s*host|--network\s+host)",
    re.IGNORECASE,
)


@dataclass
class HarnessCIFinding:
    """A security or best-practice issue in a Harness CI pipeline."""

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
class HarnessCIInfo:
    """Parsed metadata about a Harness CI pipeline file."""

    path: str
    stages: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    connectors: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class HarnessCIStats:
    """Aggregate Harness CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_harness_file(path: Path) -> bool:
    lower = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if parts & set(HARNESS_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    if lower in HARNESS_PIPELINE_NAMES and parts & set(HARNESS_DIRS):
        return True
    if any(lower.endswith(suffix) for suffix in HARNESS_SUFFIXES):
        return True
    return False


class HarnessCIAnalyzer:
    """Audit Harness CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.harness/pipeline.yaml` for curl-pipe-to-shell, privileged containers,
    plaintext pipeline variables, HARNESS_* injection in run scripts, and unpinned images.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HarnessCIFinding] | None = None
        self._stats: HarnessCIStats | None = None
        self._infos: list[HarnessCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Harness CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_harness_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[HarnessCIFinding], HarnessCIInfo]:
        findings: list[HarnessCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HarnessCIInfo(path=rel)

        info = HarnessCIInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        in_env_variables = False
        env_indent = 0
        in_command_block = False
        command_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^\s*envVariables\s*:", raw, re.IGNORECASE):
                in_env_variables = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_env_variables:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= env_indent and not line.startswith("-"):
                    in_env_variables = False

            stage_match = re.match(r"^\s*name\s*:\s*[\"']?([^\"']+)", raw, re.IGNORECASE)
            if stage_match and re.search(r"\bstage\b", raw, re.IGNORECASE):
                stage_name = stage_match.group(1).strip()
                info.stages.append(stage_name)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(stage_name))

            step_match = re.match(r"^\s*name\s*:\s*[\"']?([^\"']+)", raw, re.IGNORECASE)
            if step_match and re.search(r"\bstep\b", raw, re.IGNORECASE):
                step_name = step_match.group(1).strip()
                info.steps.append(step_name)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(step_name))

            connector_match = re.match(r"^\s*connectorRef\s*:\s*(.+)$", raw, re.IGNORECASE)
            if connector_match:
                info.connectors.append(connector_match.group(1).strip())

            if re.match(r"^\s*command\s*:", raw, re.IGNORECASE):
                in_command_block = True
                command_indent = len(raw) - len(raw.lstrip())
                continue

            if in_command_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= command_indent and not line.startswith("|"):
                    in_command_block = False

            if in_env_variables and HARDCODED_ENV_VALUE_PATTERN.match(line):
                if not re.search(r"(?:<\+|org\.|account\.|project\.)", line, re.IGNORECASE):
                    findings.append(
                        HarnessCIFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="plaintext value in envVariables — use Harness secrets or connectors",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Harness secrets manager or connectors",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="plaintext_aws_key",
                        severity="high",
                        message="plaintext AWS access key — use IAM roles or Harness secrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
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
                    HarnessCIFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image or connector uses :latest — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
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
                    HarnessCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="run_as_root",
                        severity="medium",
                        message="step runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="host_network",
                        severity="high",
                        message="host networking grants unrestricted network access to the container",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and (
                in_command_block or re.search(r"^\s*command\s*:", raw, re.IGNORECASE)
            ):
                findings.append(
                    HarnessCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="Harness expression in command — validate untrusted pipeline/trigger inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_SETTING_PATTERN.match(line):
                findings.append(
                    HarnessCIFinding(
                        kind="insecure_pipeline_setting",
                        severity="medium",
                        message="insecure pipeline setting enabled — review auto-abort and resource validation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and re.search(r"failureStrategy\s*:\s*Abort", line, re.IGNORECASE):
                if re.search(r"ignore", line, re.IGNORECASE):
                    findings.append(
                        HarnessCIFinding(
                            kind="security_failure_ignored",
                            severity="medium",
                            message="security step ignores failures — failing scans should block pipelines",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        content = "\n".join(raw_lines)
        if PLAINTEXT_PIPELINE_VAR_PATTERN.search(content):
            findings.append(
                HarnessCIFinding(
                    kind="plaintext_pipeline_variable",
                    severity="high",
                    message="plaintext pipeline variable — use Harness secrets or runtime inputs",
                    path=rel,
                    lineno=1,
                    line="pipeline variables",
                )
            )

        return findings, info

    def analyze(self) -> list[HarnessCIFinding]:
        """Scan Harness CI pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HarnessCIFinding] = []
        infos: list[HarnessCIInfo] = []
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
        self._stats = HarnessCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HarnessCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HarnessCIInfo]:
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
        """Scaffold a hardened Harness CI pipeline template."""
        return """\
# Generated by DevAI HarnessCIAnalyzer
pipeline:
  name: secure-pipeline
  identifier: secure_pipeline
  stages:
    - stage:
        name: build
        identifier: build
        spec:
          execution:
            steps:
              - step:
                  name: Run
                  identifier: run
                  type: Run
                  spec:
                    shell: Bash
                    connectorRef: account.docker
                    image: alpine:3.19
                    command: |
                      pip install -r requirements.txt
                      python -m pytest
                    envVariables:
                      DB_PASSWORD:
                        name: db_password
                        type: Secret
                        value: org.db_password
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Harness CI: none found"
        return (
            f"Harness CI: {stats.pipelines} pipeline(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Harness CI pipeline analysis:",
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
