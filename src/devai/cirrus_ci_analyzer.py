"""CirrusCIAnalyzer — audit Cirrus CI pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIRRUS_FILENAMES = (".cirrus.yml", ".cirrus.yaml", "cirrus.yml", "cirrus.yaml")
CIRRUS_DIRS = (".cirrus", "cirrus", "ci/cirrus")
CIRRUS_SUFFIXES = (".cirrus.yml", ".cirrus.yaml")

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
    r"^\s*privileged\s*:\s*true\s*$",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"^\s*(?:network_mode|network)\s*:\s*[\"']?host[\"']?\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$CIRRUS_(?:CHANGE_IN_REPO|BRANCH|CHANGE_TITLE|COMMIT_MESSAGE|PR_TITLE|PR_BODY|"
    r"CHANGE_AUTHOR|CHANGE_MESSAGE|TAG|BASE_BRANCH|HEAD_BRANCH)",
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
TASK_NAME_PATTERN = re.compile(
    r"^\s*([a-zA-Z0-9_.-]+)_task\s*:\s*$",
    re.IGNORECASE,
)
SKIP_TLS_VERIFY_PATTERN = re.compile(
    r"^\s*skip_tls_verify\s*:\s*true\s*$",
    re.IGNORECASE,
)
INSECURE_KUBELET_PATTERN = re.compile(
    r"^\s*use_insecure_kubelet_readonly_port\s*:\s*true\s*$",
    re.IGNORECASE,
)
STATIC_CREDENTIALS_PATTERN = re.compile(
    r"^\s*use_static_credentials\s*:\s*true\s*$",
    re.IGNORECASE,
)


@dataclass
class CirrusCIFinding:
    """A security or best-practice issue in a Cirrus CI pipeline."""

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
class CirrusCIInfo:
    """Parsed metadata about a Cirrus CI pipeline file."""

    path: str
    tasks: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CirrusCIStats:
    """Aggregate Cirrus CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cirrus_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in CIRRUS_FILENAMES:
        return True
    if any(lower.endswith(suffix) for suffix in CIRRUS_SUFFIXES):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(CIRRUS_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    return False


class CirrusCIAnalyzer:
    """Audit Cirrus CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.cirrus.yml` files for curl-pipe-to-shell, privileged containers,
    host networking, unpinned image tags, and CIRRUS_* variable injection in scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CirrusCIFinding] | None = None
        self._stats: CirrusCIStats | None = None
        self._infos: list[CirrusCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Cirrus CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cirrus_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CirrusCIFinding], CirrusCIInfo]:
        findings: list[CirrusCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CirrusCIInfo(path=rel)

        info = CirrusCIInfo(path=rel, lines=len(raw_lines))
        in_security_task = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            task_match = TASK_NAME_PATTERN.match(raw)
            if task_match:
                task_name = task_match.group(1).strip()
                info.tasks.append(task_name)
                in_security_task = bool(SECURITY_STEP_PATTERN.search(task_name))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Cirrus encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_VALUE_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="hardcoded_secret_value",
                        severity="high",
                        message="hardcoded secret value pattern — use Cirrus encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ENV_VAR_SECRET_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="plaintext_env_secret",
                        severity="high",
                        message="plaintext secret in env block — use encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
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
                    CirrusCIFinding(
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
                    CirrusCIFinding(
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
                    CirrusCIFinding(
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
                    CirrusCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged: true — run containers without elevated privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode — containers share host network namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="script_injection",
                        severity="high",
                        message="CIRRUS variable in script — sanitize PR/branch inputs to prevent injection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path mounted into container",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_TLS_VERIFY_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="insecure_skip_verify",
                        severity="high",
                        message="skip_tls_verify: true — enable TLS certificate verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_KUBELET_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="insecure_kubelet",
                        severity="high",
                        message="use_insecure_kubelet_readonly_port: true — disable insecure kubelet access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if STATIC_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    CirrusCIFinding(
                        kind="static_credentials",
                        severity="medium",
                        message="use_static_credentials: true — prefer workload identity or short-lived tokens",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and not in_security_task:
                findings.append(
                    CirrusCIFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP URL — use HTTPS for external endpoints",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[CirrusCIFinding]:
        """Scan Cirrus CI pipeline files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CirrusCIFinding] = []
        infos: list[CirrusCIInfo] = []
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
        self._stats = CirrusCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CirrusCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CirrusCIInfo]:
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
        """Scaffold a hardened Cirrus CI pipeline template."""
        return """\
# Generated by DevAI CirrusCIAnalyzer
task:
  ubuntu_instance:
    image: ubuntu:24.04

  env:
    PYTHON_VERSION: "3.12"

  test_script: |
    pip install -e '.[dev]'
    python -m pytest

security_scan_task:
  ubuntu_instance:
    image: ubuntu:24.04

  test_script: |
    pip install devai
    devai security-scan .
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Cirrus CI: none found"
        return (
            f"Cirrus CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Cirrus CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            tasks = ", ".join(info.tasks[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.tasks)} task(s), tasks=[{tasks}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
