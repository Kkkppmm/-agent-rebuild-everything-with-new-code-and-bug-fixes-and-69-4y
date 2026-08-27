"""GoCDCIAnalyzer — audit GoCD pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GOCD_FILENAMES = ("gocd.yaml", "gocd.yml", "gocd-config.yaml", "gocd-config.yml")
GOCD_DIRS = (".gocd", "gocd", "ci/gocd", "pipelines/gocd")
GOCD_SUFFIXES = (".gocd.yaml", ".gocd.yml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_VALUE_PATTERN = re.compile(
    r"^\s*value\s*:\s*[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
ENV_VAR_SECRET_PATTERN = re.compile(
    r"^\s*(?:[A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY)[A-Z0-9_]*)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|docker_image|container_image)\s*:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"^\s*(?:privileged|run_privileged)\s*:\s*true\s*$",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"^\s*(?:hostNetwork|host_network|network_mode)\s*:\s*[\"']?host[\"']?\s*$",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(
    r"^\s*(?:runAsUser|run_as_user)\s*:\s*0\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$GO_(?:TRIGGER_USER|MATERIAL_BRANCH|MATERIAL_URL|PIPELINE_NAME|STAGE_NAME|JOB_NAME|REVISION|COMMIT_MESSAGE)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
FLOATING_IMAGE_TAG_PATTERN = re.compile(
    r"(?:image|docker_image|container_image)\s*:\s*[^\s:]+:(?:master|main|develop)\b",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"/(?:etc/passwd|etc/shadow|root|home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
PIPELINE_KEY_PATTERN = re.compile(
    r"^\s{2}([a-zA-Z0-9_.-]+)\s*:\s*$",
)
STAGE_KEY_PATTERN = re.compile(
    r"^\s{4,6}-\s*([a-zA-Z0-9_.-]+)\s*:\s*$",
)
JOB_KEY_PATTERN = re.compile(
    r"^\s{6,10}([a-zA-Z0-9_.-]+)\s*:\s*$",
)
INSECURE_SKIP_VERIFY_PATTERN = re.compile(
    r"^\s*(?:insecure_skip_verify|skip_ssl_verification|ignore_ssl)\s*:\s*true\s*$",
    re.IGNORECASE,
)


@dataclass
class GoCDCIFinding:
    """A security or best-practice issue in a GoCD pipeline."""

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
class GoCDCIInfo:
    """Parsed metadata about a GoCD pipeline file."""

    path: str
    pipelines: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class GoCDCIStats:
    """Aggregate GoCD CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gocd_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in GOCD_FILENAMES:
        return True
    if any(lower.endswith(suffix) for suffix in GOCD_SUFFIXES):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(GOCD_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    return False


class GoCDCIAnalyzer:
    """Audit GoCD pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.gocd/` YAML files for curl-pipe-to-shell, privileged containers,
    host networking, unpinned image tags, and GO_* variable injection in tasks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GoCDCIFinding] | None = None
        self._stats: GoCDCIStats | None = None
        self._infos: list[GoCDCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return GoCD pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_gocd_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GoCDCIFinding], GoCDCIInfo]:
        findings: list[GoCDCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GoCDCIInfo(path=rel)

        info = GoCDCIInfo(path=rel, lines=len(raw_lines))
        in_pipelines = False
        in_security_task = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^\s*pipelines\s*:\s*$", raw, re.IGNORECASE):
                in_pipelines = True
                continue

            if in_pipelines:
                pipeline_match = PIPELINE_KEY_PATTERN.match(raw)
                if pipeline_match:
                    info.pipelines.append(pipeline_match.group(1).strip())

            stage_match = STAGE_KEY_PATTERN.match(raw)
            if stage_match:
                stage_name = stage_match.group(1).strip()
                info.stages.append(stage_name)
                in_security_task = bool(SECURITY_STEP_PATTERN.search(stage_name))

            job_match = JOB_KEY_PATTERN.match(raw)
            if job_match:
                job_name = job_match.group(1).strip()
                if job_name not in ("tasks", "artifacts", "environment_variables", "secure_variables"):
                    info.jobs.append(job_name)
                    if SECURITY_STEP_PATTERN.search(job_name):
                        in_security_task = True

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use GoCD secure_variables or secret plugins",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ENV_VAR_SECRET_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="plaintext_env_secret",
                        severity="high",
                        message="plaintext environment variable secret — use secure_variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_VALUE_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="hardcoded_secret_value",
                        severity="high",
                        message="hardcoded secret value pattern — use GoCD secret management",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
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
                    GoCDCIFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="container image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_IMAGE_TAG_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="floating_image_tag",
                        severity="medium",
                        message="container image uses a floating branch tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount exposes host — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container — run tasks without elevated privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode — containers share host network namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="run_as_root",
                        severity="high",
                        message="runAsUser: 0 — run containers as a non-root user",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="script_injection",
                        severity="high",
                        message="GO_* variable in script — sanitize trigger/material inputs to prevent injection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path mounted into container",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_SKIP_VERIFY_PATTERN.search(line):
                findings.append(
                    GoCDCIFinding(
                        kind="insecure_skip_verify",
                        severity="high",
                        message="TLS verification disabled — enable certificate validation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and not in_security_task:
                findings.append(
                    GoCDCIFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP URL — use HTTPS for external endpoints",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[GoCDCIFinding]:
        """Scan GoCD pipeline files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GoCDCIFinding] = []
        infos: list[GoCDCIInfo] = []
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
        self._stats = GoCDCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GoCDCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GoCDCIInfo]:
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
        """Scaffold a hardened GoCD pipeline template."""
        return """\
# Generated by DevAI GoCDCIAnalyzer
format_version: 10
pipelines:
  main-pipeline:
    group: defaultGroup
    materials:
      git:
        url: https://github.com/org/repo.git
        branch: main
        shallow_clone: true
    environment_variables:
      PYTHON_VERSION: "3.12"
    stages:
      - test:
          clean_workspace: true
          jobs:
            unit-tests:
              tasks:
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - pip install -e '.[dev]' && python -m pytest
              artifacts:
                - test:
                    source: reports/
                    destination: test-reports

      - security-scan:
          clean_workspace: true
          jobs:
            scan:
              tasks:
                - exec:
                    command: bash
                    arguments:
                      - -c
                      - pip install devai && devai security-scan .
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "GoCD CI: none found"
        return (
            f"GoCD CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GoCD CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.pipelines)} pipeline(s), stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
