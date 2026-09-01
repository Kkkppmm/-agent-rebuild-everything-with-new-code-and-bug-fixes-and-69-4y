"""ConcourseCIAnalyzer — audit Concourse CI pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONCOURSE_FILENAMES = (
    "pipeline.yml",
    "pipeline.yaml",
    "concourse.yml",
    "concourse.yaml",
)
CONCOURSE_DIRS = ("ci", "concourse", ".concourse", "pipelines")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_SOURCE_VALUE_PATTERN = re.compile(
    r"^\s*(?:password|token|private_key|access_token|client_secret)\s*:\s*"
    r"(?!\(\()[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|repository)\s*:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"^\s*privileged\s*:\s*true\s*$",
    re.IGNORECASE,
)
INSECURE_SKIP_VERIFY_PATTERN = re.compile(
    r"^\s*insecure_skip_verify\s*:\s*true\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?\s*(?:\(\.:)?(?:git\.ref|git\.branch|pull-request|commit|build\.id|version)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SENSITIVE_CACHE_PATTERN = re.compile(
    r"^\s*-\s*(?:/root/\.ssh|/etc/passwd|/etc/shadow|/root)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)
PUBLICLY_EXPOSED_PATTERN = re.compile(
    r"^\s*publicly_exposed_plan\s*:\s*true\s*$",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"^\s*(?:password|token|private_key)\s*:\s*[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
UNPINNED_RESOURCE_PATTERN = re.compile(
    r"^\s*type\s*:\s*(?:docker-image|registry-image)\s*$",
    re.IGNORECASE,
)
FLOATING_TAG_PATTERN = re.compile(
    r"^\s*tag\s*:\s*(?:latest|master|main|develop)\s*$",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"^\s*user\s*:\s*root\s*$",
    re.IGNORECASE,
)
HARDCODED_PARAM_PATTERN = re.compile(
    r"^\s*(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|DOCKER_PASSWORD)\s*:\s*"
    r"(?!\(\()[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)


@dataclass
class ConcourseCIFinding:
    """A security or best-practice issue in a Concourse CI pipeline."""

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
class ConcourseCIInfo:
    """Parsed metadata about a Concourse CI pipeline file."""

    path: str
    jobs: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class ConcourseCIStats:
    """Aggregate Concourse CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_concourse_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in CONCOURSE_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(CONCOURSE_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    if lower.endswith(".pipeline.yml") or lower.endswith(".pipeline.yaml"):
        return True
    return False


class ConcourseCIAnalyzer:
    """Audit Concourse CI pipelines for hardcoded secrets, privileged tasks, and unsafe scripts.

    Scans `ci/pipeline.yml` for curl-pipe-to-shell, hardcoded resource source credentials,
    privileged tasks, insecure_skip_verify, and Concourse variable injection in run scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ConcourseCIFinding] | None = None
        self._stats: ConcourseCIStats | None = None
        self._infos: list[ConcourseCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Concourse CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_concourse_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[ConcourseCIFinding], ConcourseCIInfo]:
        findings: list[ConcourseCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, ConcourseCIInfo(path=rel)

        info = ConcourseCIInfo(path=rel, lines=len(raw_lines))
        in_security_job = False
        current_job = ""
        in_run_block = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^\s*jobs\s*:", raw) or re.match(r"^\s*-\s*name\s*:", raw):
                job_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
                if job_match and "jobs:" in content:
                    current_job = job_match.group(1).strip().strip("\"'")
                    info.jobs.append(current_job)
                    in_security_job = bool(SECURITY_STEP_PATTERN.search(current_job))

            resource_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
            if resource_match:
                context = "\n".join(raw_lines[max(0, lineno - 12):lineno + 1])
                if "resources:" in context and "jobs:" not in context.split("jobs:")[-1]:
                    name = resource_match.group(1).strip().strip("\"'")
                    if name not in info.jobs:
                        info.resources.append(name)

            type_match = re.match(r"^\s*type\s*:\s*(.+)$", raw)
            if type_match and "resource_types:" in content:
                context = "\n".join(raw_lines[max(0, lineno - 8):lineno])
                if "resource_types:" in context:
                    info.resource_types.append(type_match.group(1).strip().strip("\"'"))

            if re.match(r"^\s*run\s*:", raw):
                in_run_block = True
            elif in_run_block and re.match(r"^\s*\w+\s*:", raw) and not raw.startswith(" " * 4):
                in_run_block = False

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Concourse credentials or ((var)) interpolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_SOURCE_VALUE_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="hardcoded_source_secret",
                        severity="high",
                        message="hardcoded secret in resource source — use Concourse credentials manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAIN_SECRET_VALUE_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="plain_secret_value",
                        severity="high",
                        message="sensitive-looking value in source/params — store in Concourse credentials",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_PARAM_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="hardcoded_param",
                        severity="high",
                        message="hardcoded secret in task params — use ((credential)) interpolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    ConcourseCIFinding(
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
                    ConcourseCIFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="privileged_task",
                        severity="high",
                        message="privileged task grants full host access — avoid unless required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_SKIP_VERIFY_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="insecure_skip_verify",
                        severity="high",
                        message="TLS verification disabled — remove insecure_skip_verify in production",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and (in_run_block or "run:" in raw):
                findings.append(
                    ConcourseCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="Concourse variable interpolated in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_CACHE_PATTERN.search(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="sensitive_cache",
                        severity="high",
                        message="sensitive host path used as cache — avoid caching credentials or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLICLY_EXPOSED_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="publicly_exposed_plan",
                        severity="medium",
                        message="publicly_exposed_plan enabled — pipeline plan may leak sensitive metadata",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="root_user",
                        severity="medium",
                        message="task runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_TAG_PATTERN.match(line):
                findings.append(
                    ConcourseCIFinding(
                        kind="floating_image_tag",
                        severity="low",
                        message="floating image tag — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_RESOURCE_PATTERN.match(line):
                context = "\n".join(raw_lines[lineno - 1: min(len(raw_lines), lineno + 6)])
                if FLOATING_TAG_PATTERN.search(context) or "tag:" not in context:
                    findings.append(
                        ConcourseCIFinding(
                            kind="unpinned_resource_image",
                            severity="low",
                            message="docker/registry image without pinned tag — specify an immutable tag",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        return findings, info

    def analyze(self) -> list[ConcourseCIFinding]:
        """Scan Concourse CI pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ConcourseCIFinding] = []
        infos: list[ConcourseCIInfo] = []
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
        self._stats = ConcourseCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ConcourseCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ConcourseCIInfo]:
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
        """Scaffold a hardened Concourse CI pipeline template."""
        return """\
# Generated by DevAI ConcourseCIAnalyzer
resource_types: []

resources:
  - name: repo
    type: git
    source:
      uri: ((git-uri))
      branch: main
      private_key: ((git-private-key))

jobs:
  - name: unit-tests
    plan:
      - get: repo
        trigger: true
      - task: test
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: python
              tag: "3.12-slim"
          inputs:
            - name: repo
          run:
            path: sh
            args:
              - -exc
              - |
                cd repo
                pip install -e ".[dev]"
                python -m pytest

  - name: security-scan
    plan:
      - get: repo
        passed: [unit-tests]
      - task: scan
        config:
          platform: linux
          image_resource:
            type: registry-image
            source:
              repository: python
              tag: "3.12-slim"
          inputs:
            - name: repo
          run:
            path: sh
            args:
              - -exc
              - |
                cd repo
                pip install devai
                devai security-scan .
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Concourse CI: none found"
        return (
            f"Concourse CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Concourse CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            jobs = ", ".join(info.jobs[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.jobs)} job(s), jobs=[{jobs}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
