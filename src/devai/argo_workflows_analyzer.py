"""ArgoWorkflowsAnalyzer — audit Argo Workflows configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

ARGO_FILENAMES = (
    "workflow.yaml",
    "workflow.yml",
    "workflowtemplate.yaml",
    "workflowtemplate.yml",
    "cronworkflow.yaml",
    "cronworkflow.yml",
)
ARGO_DIRS = (".argo", "argo", "workflows", "ci/argo", "manifests/argo")

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
    r"\{\{(?:inputs|workflow|tasks|steps|item|retries|pod|artifacts|parameters)\.[^}]+\}\}",
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
ARGO_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*argoproj\.io/",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"(?:image|name)\s*:\s*[\"']?(?:ubuntu|node|python|golang|alpine)[\"']?\s*$",
    re.IGNORECASE,
)
SKIP_SECURITY_PATTERN = re.compile(
    r"(?:continueOn|onExit)\s*:\s*(?:failed|error)",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"hostNetwork\s*:\s*true",
    re.IGNORECASE,
)
HOST_PID_PATTERN = re.compile(
    r"hostPID\s*:\s*true",
    re.IGNORECASE,
)


@dataclass
class ArgoWorkflowsFinding:
    """A security or best-practice issue in an Argo Workflows config."""

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
class ArgoWorkflowsInfo:
    """Parsed metadata about an Argo Workflows config file."""

    path: str
    kind: str = ""
    templates: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class ArgoWorkflowsStats:
    """Aggregate Argo Workflows analysis statistics."""

    workflows: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_argo_workflows_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in ARGO_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(ARGO_DIRS):
        if lower.endswith((".yml", ".yaml")):
            return True
    if lower.endswith(".argo.yaml") or lower.endswith(".argo.yml"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
        if ARGO_API_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


class ArgoWorkflowsAnalyzer:
    """Audit Argo Workflows for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans Workflow/WorkflowTemplate/CronWorkflow YAML for curl-pipe-to-shell,
    parameter injection in scripts, privileged securityContext, hostPath mounts,
    and secrets in env blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ArgoWorkflowsFinding] | None = None
        self._stats: ArgoWorkflowsStats | None = None
        self._infos: list[ArgoWorkflowsInfo] | None = None

    def files(self) -> list[Path]:
        """Return Argo Workflows config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_argo_workflows_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[ArgoWorkflowsFinding], ArgoWorkflowsInfo]:
        findings: list[ArgoWorkflowsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, ArgoWorkflowsInfo(path=rel)

        info = ArgoWorkflowsInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        current_template = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = re.match(r"^\s*kind\s*:\s*(.+)$", raw, re.I)
            if kind_match:
                info.kind = kind_match.group(1).strip().strip("\"'")

            template_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
            if template_match and ("templates:" in content or "workflowSpec:" in content):
                current_template = template_match.group(1).strip().strip("\"'")
                info.templates.append(current_template)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(current_template))

            image_match = re.match(r"^\s*image\s*:\s*(.+)$", raw, re.I)
            if image_match:
                img = image_match.group(1).strip().strip("\"'")
                info.images.append(img)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    ArgoWorkflowsFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Argo secrets and secretKeyRef",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.match(r"^\s*-\s*name\s*:\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD)", raw, re.I):
                value_line = raw_lines[lineno] if lineno < len(raw_lines) else ""
                if re.search(r"value\s*:\s*[\"'][^\"'{}\s]", value_line, re.I):
                    findings.append(
                        ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged securityContext grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and re.search(
                r"(?:script|args|command|sh|bash|source)", line, re.I
            ):
                findings.append(
                    ArgoWorkflowsFinding(
                        kind="script_injection",
                        severity="medium",
                        message="Argo expression in script — quote parameters and validate inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
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
                    ArgoWorkflowsFinding(
                        kind="unpinned_image",
                        severity="low",
                        message="unpinned base image — specify a version tag or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line) or HOST_PID_PATTERN.search(line):
                findings.append(
                    ArgoWorkflowsFinding(
                        kind="host_namespace",
                        severity="high",
                        message="hostNetwork or hostPID grants host-level namespace access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and SKIP_SECURITY_PATTERN.search(line):
                findings.append(
                    ArgoWorkflowsFinding(
                        kind="skip_security_step",
                        severity="high",
                        message="security step configured to continue on failure",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[ArgoWorkflowsFinding]:
        """Scan Argo Workflows configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ArgoWorkflowsFinding] = []
        infos: list[ArgoWorkflowsInfo] = []
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
        self._stats = ArgoWorkflowsStats(
            workflows=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ArgoWorkflowsStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ArgoWorkflowsInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no workflows)."""
        self.analyze()
        stats = self.stats
        if stats.workflows == 0:
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
        """Scaffold a hardened Argo Workflow template."""
        return """\
# Generated by DevAI ArgoWorkflowsAnalyzer
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: devai-workflow-
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: git-revision
        value: main
  templates:
    - name: main
      steps:
        - - name: test
            template: pytest
        - - name: security-scan
            template: trivy-scan

    - name: pytest
      inputs:
        artifacts:
          - name: source
            path: /src
      container:
        image: python:3.12-slim
        workingDir: /src
        command: [python, -m, pytest]
        env:
          - name: PYPI_TOKEN
            valueFrom:
              secretKeyRef:
                name: pypi-credentials
                key: token
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false

    - name: trivy-scan
      inputs:
        artifacts:
          - name: source
            path: /src
      container:
        image: ghcr.io/aquasecurity/trivy:0.58.0
        workingDir: /src
        command: [trivy, fs, --severity, HIGH,CRITICAL, .]
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.workflows == 0:
            return "Argo Workflows: none found"
        return (
            f"Argo Workflows: {stats.workflows} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Argo Workflows audit (health score: {self.health_score()}/100)",
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
