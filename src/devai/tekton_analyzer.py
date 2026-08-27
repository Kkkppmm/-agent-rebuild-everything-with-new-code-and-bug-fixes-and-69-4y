"""TektonAnalyzer — audit Tekton Pipeline/Task configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TEKTON_FILENAMES = (
    "pipeline.yaml",
    "pipeline.yml",
    "task.yaml",
    "task.yml",
    "pipelinerun.yaml",
    "pipelinerun.yml",
    "taskrun.yaml",
    "taskrun.yml",
)
TEKTON_DIRS = (".tekton", "tekton", "ci/tekton", "pipelines/tekton")

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
    r"(?:image|name)[^\n]*:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\((?:params|workspaces|context|tasks|pipeline|version|git|image)\.[^)]+\)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"(?:/etc/passwd|/etc/shadow|/root|/home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false)",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"(?:hostPath|host\s+path)\s*:\s*(?:/var/run/docker\.sock|/etc|/root|/proc|/sys)",
    re.IGNORECASE,
)
TEKTON_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*tekton\.dev/",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"(?:image|name)\s*:\s*[\"']?(?:ubuntu|node|python|golang|alpine)[\"']?\s*$",
    re.IGNORECASE,
)
SKIP_SECURITY_PATTERN = re.compile(
    r"(?:onError|retries)\s*:\s*(?:continue|ignore)",
    re.IGNORECASE,
)


@dataclass
class TektonFinding:
    """A security or best-practice issue in a Tekton pipeline."""

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
class TektonInfo:
    """Parsed metadata about a Tekton config file."""

    path: str
    kind: str = ""
    tasks: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TektonStats:
    """Aggregate Tekton analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_tekton_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in TEKTON_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(TEKTON_DIRS):
        if lower.endswith((".yml", ".yaml")):
            return True
    if lower.endswith(".tekton.yaml") or lower.endswith(".tekton.yml"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
        if TEKTON_API_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


class TektonAnalyzer:
    """Audit Tekton pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans Pipeline/Task YAML for curl-pipe-to-shell, parameter injection in scripts,
    privileged securityContext, hostPath mounts, and secrets in env blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TektonFinding] | None = None
        self._stats: TektonStats | None = None
        self._infos: list[TektonInfo] | None = None

    def files(self) -> list[Path]:
        """Return Tekton config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_tekton_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TektonFinding], TektonInfo]:
        findings: list[TektonFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, TektonInfo(path=rel)

        info = TektonInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        current_task = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = re.match(r"^\s*kind\s*:\s*(.+)$", raw, re.I)
            if kind_match:
                info.kind = kind_match.group(1).strip().strip("\"'")

            task_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
            if task_match and ("tasks:" in content or "pipelineSpec:" in content):
                current_task = task_match.group(1).strip().strip("\"'")
                info.tasks.append(current_task)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(current_task))

            image_match = re.match(r"^\s*image\s*:\s*(.+)$", raw, re.I)
            if image_match:
                img = image_match.group(1).strip().strip("\"'")
                info.images.append(img)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Tekton secrets and secretKeyRef",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.match(r"^\s*-\s*name\s*:\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD)", raw, re.I):
                value_line = raw_lines[lineno] if lineno < len(raw_lines) else ""
                if re.search(r"value\s*:\s*[\"'][^\"'{}\s]", value_line, re.I):
                    findings.append(
                        TektonFinding(
                            kind="hardcoded_env",
                            severity="high",
                            message="hardcoded env value — use valueFrom.secretKeyRef",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if PLAIN_SECRET_VALUE_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="plain_secret_value",
                        severity="high",
                        message="sensitive-looking value in config — store in Kubernetes secrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TektonFinding(
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
                    TektonFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line) or HOST_PATH_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="host_path_mount",
                        severity="high",
                        message="hostPath or docker socket mount grants host-level access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged securityContext grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and re.search(
                r"(?:script|args|command|sh|bash)", line, re.I
            ):
                findings.append(
                    TektonFinding(
                        kind="script_injection",
                        severity="medium",
                        message="Tekton substitution in script — quote parameters and validate inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP URL — use HTTPS for remote endpoints",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path in volume mount",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="root_user",
                        severity="medium",
                        message="container runs as root or without runAsNonRoot",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_IMAGE_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="unpinned_image",
                        severity="low",
                        message="unpinned base image — specify a version tag or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and SKIP_SECURITY_PATTERN.search(line):
                findings.append(
                    TektonFinding(
                        kind="skip_security_step",
                        severity="high",
                        message="security step configured to continue on error",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[TektonFinding]:
        """Scan Tekton configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TektonFinding] = []
        infos: list[TektonInfo] = []
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
        self._stats = TektonStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TektonStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TektonInfo]:
        """Return parsed config metadata."""
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
        """Scaffold a hardened Tekton Pipeline template."""
        return """\
# Generated by DevAI TektonAnalyzer
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: devai-pipeline
spec:
  params:
    - name: git-url
      type: string
    - name: git-revision
      type: string
      default: main
  workspaces:
    - name: shared-workspace
  tasks:
    - name: test
      taskSpec:
        workspaces:
          - name: source
            workspace: shared-workspace
        steps:
          - name: pytest
            image: python:3.12-slim
            workingDir: $(workspaces.source.path)
            script: |
              pip install -e ".[dev]"
              python -m pytest
            env:
              - name: PYPI_TOKEN
                valueFrom:
                  secretKeyRef:
                    name: pypi-credentials
                    key: token
            securityContext:
              runAsNonRoot: true
              allowPrivilegeEscalation: false

    - name: security-scan
      runAfter:
        - test
      taskSpec:
        workspaces:
          - name: source
            workspace: shared-workspace
        steps:
          - name: scan
            image: ghcr.io/aquasecurity/trivy:0.58.0
            workingDir: $(workspaces.source.path)
            script: |
              trivy fs --severity HIGH,CRITICAL .
            securityContext:
              runAsNonRoot: true
              allowPrivilegeEscalation: false
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Tekton: none found"
        return (
            f"Tekton: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Tekton pipeline audit (health score: {self.health_score()}/100)",
            self.summary(),
        ]
        if self._infos:
            for info in self._infos:
                kind = info.kind or "unknown"
                lines.append(f"  - {info.path} ({kind}, {info.lines} lines)")
        findings = self._findings or []
        if findings:
            lines.append("Findings:")
            for finding in findings[:30]:
                lines.append(f"  {finding.format()}")
            if len(findings) > 30:
                lines.append(f"  ... and {len(findings) - 30} more")
        return "\n".join(lines)
