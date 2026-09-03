"""SemaphoreCIAnalyzer — audit Semaphore CI pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SEMAPHORE_FILENAMES = (
    "semaphore.yml",
    "semaphore.yaml",
    ".semaphore.yml",
    ".semaphore.yaml",
)
SEMAPHORE_DIRS = (".semaphore", "semaphore", "ci")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*\n"
    r"\s*value\s*:\s*[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE | re.MULTILINE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|docker):\s*[^\s:]+:latest\b",
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
    r"^\s*network_mode\s*:\s*host\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?\s*SEMAPHORE_(?:GIT_PR_NUMBER|GIT_BRANCH|GIT_SHA|GIT_REF|GIT_COMMIT_RANGE|"
    r"WORKFLOW_ID|ORGANIZATION_URL|JOB_NAME)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"^\s*-\s*/(?:etc/passwd|etc/shadow|root|home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"^\s*user\s*:\s*root\s*$",
    re.IGNORECASE,
)
AUTO_PROMOTE_PATTERN = re.compile(
    r"^\s*auto_promote\s*:",
    re.IGNORECASE,
)
BROAD_AUTO_PROMOTE_PATTERN = re.compile(
    r"when\s*:\s*[\"'].*(?:branch\s*=\s*['\"]?\*|true|always).*[\"']",
    re.IGNORECASE,
)
UNPINNED_AGENT_IMAGE_PATTERN = re.compile(
    r"^\s*os_image\s*:\s*(?:ubuntu|macos)[\"']?\s*$",
    re.IGNORECASE,
)
SKIP_SECURITY_PATTERN = re.compile(
    r"^\s*skip\s*:\s*true\s*$",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"^\s*value\s*:\s*[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)


@dataclass
class SemaphoreCIFinding:
    """A security or best-practice issue in a Semaphore CI pipeline."""

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
class SemaphoreCIInfo:
    """Parsed metadata about a Semaphore CI pipeline file."""

    path: str
    blocks: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class SemaphoreCIStats:
    """Aggregate Semaphore CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_semaphore_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in SEMAPHORE_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(SEMAPHORE_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    if lower.endswith(".semaphore.yml") or lower.endswith(".semaphore.yaml"):
        return True
    return False


class SemaphoreCIAnalyzer:
    """Audit Semaphore CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.semaphore/semaphore.yml` for curl-pipe-to-shell, auto-promote rules,
    SEMAPHORE_* variable injection, and secrets in environment blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SemaphoreCIFinding] | None = None
        self._stats: SemaphoreCIStats | None = None
        self._infos: list[SemaphoreCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Semaphore CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_semaphore_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[SemaphoreCIFinding], SemaphoreCIInfo]:
        findings: list[SemaphoreCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, SemaphoreCIInfo(path=rel)

        info = SemaphoreCIInfo(path=rel, lines=len(raw_lines))
        in_security_block = False
        current_block = ""
        current_job = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            block_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
            if block_match and "blocks:" in content:
                current_block = block_match.group(1).strip().strip("\"'")
                info.blocks.append(current_block)
                in_security_block = bool(SECURITY_STEP_PATTERN.search(current_block))

            job_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
            if job_match and "jobs:" in "\n".join(raw_lines[max(0, lineno - 8):lineno]):
                current_job = job_match.group(1).strip().strip("\"'")
                info.jobs.append(current_job)
                if SECURITY_STEP_PATTERN.search(current_job):
                    in_security_block = True

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Semaphore secrets ($SECRET_NAME)",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAIN_SECRET_VALUE_PATTERN.match(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="plain_secret_value",
                        severity="high",
                        message="sensitive-looking value in env_vars — store in Semaphore secrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    SemaphoreCIFinding(
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
                    SemaphoreCIFinding(
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
                    SemaphoreCIFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="host_network",
                        severity="high",
                        message="host network mode bypasses container network isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="SEMAPHORE_* variable interpolated in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path mounted into container — avoid mounting credentials or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.match(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="root_user",
                        severity="medium",
                        message="step runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AUTO_PROMOTE_PATTERN.match(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="auto_promote",
                        severity="medium",
                        message="auto-promote enabled — ensure promotion rules restrict production deploys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if BROAD_AUTO_PROMOTE_PATTERN.search(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="broad_auto_promote",
                        severity="high",
                        message="auto-promote matches all branches — restrict to protected branches",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_AGENT_IMAGE_PATTERN.match(line):
                findings.append(
                    SemaphoreCIFinding(
                        kind="unpinned_agent_image",
                        severity="low",
                        message="agent os_image not version-pinned — pin to a specific image version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_SECURITY_PATTERN.match(line) and in_security_block:
                findings.append(
                    SemaphoreCIFinding(
                        kind="security_step_skipped",
                        severity="medium",
                        message="security block/job marked skip — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if HARDCODED_ENV_VALUE_PATTERN.search(content):
            for match in HARDCODED_ENV_VALUE_PATTERN.finditer(content):
                lineno = content[: match.start()].count("\n") + 1
                findings.append(
                    SemaphoreCIFinding(
                        kind="hardcoded_env_value",
                        severity="high",
                        message="hardcoded secret in env_vars block — use Semaphore secrets",
                        path=rel,
                        lineno=lineno,
                        line=match.group(0).splitlines()[0].strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[SemaphoreCIFinding]:
        """Scan Semaphore CI pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SemaphoreCIFinding] = []
        infos: list[SemaphoreCIInfo] = []
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
        self._stats = SemaphoreCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SemaphoreCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SemaphoreCIInfo]:
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
        """Scaffold a hardened Semaphore CI pipeline template."""
        return """\
# Generated by DevAI SemaphoreCIAnalyzer
version: v1.0
name: CI
agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu2004

blocks:
  - name: Tests
    task:
      jobs:
        - name: Run tests
          commands:
            - checkout
            - pip install -e ".[dev]"
            - python -m pytest

  - name: Security scan
    task:
      jobs:
        - name: Static analysis
          commands:
            - checkout
            - pip install devai
            - devai security-scan .

promotions:
  - name: Production deploy
    pipeline_file: deploy.yml
    auto_promote:
      when: "branch = 'main' and change_in('/src/**', {default_branch: 'main'})"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Semaphore CI: none found"
        return (
            f"Semaphore CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Semaphore CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            blocks = ", ".join(info.blocks[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.blocks)} block(s), blocks=[{blocks}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
