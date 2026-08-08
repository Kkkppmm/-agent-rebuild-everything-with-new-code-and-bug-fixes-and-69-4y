"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIR_NAMES = frozenset(
    {"k8s", "kubernetes", "manifests", "deploy", "deployment", "charts", "helm"}
)
K8S_KINDS = frozenset(
    {
        "Deployment",
        "Pod",
        "StatefulSet",
        "DaemonSet",
        "Job",
        "CronJob",
        "ReplicaSet",
    }
)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(r"^\s*hostPath:\s*", re.IGNORECASE)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
SECRET_ENV_NAME_PATTERN = re.compile(
    r"name:\s*.*(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
KIND_PATTERN = re.compile(r"^\s*kind:\s*(\S+)", re.IGNORECASE)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(limits:\s*$|resources:\s*$|memory:\s*|cpu:\s*|cpus?:\s*)",
    re.IGNORECASE,
)
RUN_AS_USER_PATTERN = re.compile(r"^\s*runAsUser:\s+", re.IGNORECASE)


@dataclass
class KubernetesFinding:
    """A security or best-practice issue in a Kubernetes manifest."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    resource: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        res = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{res} — {self.message}"


@dataclass
class KubernetesInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    parts_lower = {p.lower() for p in path.parts}
    if parts_lower & K8S_DIR_NAMES:
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    if "apiVersion:" not in head:
        return False
    kind_match = re.search(r"^\s*kind:\s*(\S+)", head, re.MULTILINE | re.IGNORECASE)
    if not kind_match:
        return False
    return kind_match.group(1) in K8S_KINDS


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged pods, host namespaces, hostPath volumes, :latest image
    tags, secrets in env literals, missing resource limits, and unsafe security
    contexts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[KubernetesFinding] | None = None
        self._stats: KubernetesStats | None = None
        self._infos: list[KubernetesInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        in_security_context = False
        in_capabilities = False
        cap_mode = ""
        in_env = False
        env_indent = 0
        has_run_as_user = False
        has_resource_limits = False
        container_name = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = KIND_PATTERN.match(line)
            if kind_match:
                kind = kind_match.group(1)
                if kind not in info.kinds:
                    info.kinds.append(kind)
                current_resource = kind
                in_security_context = False
                in_capabilities = False
                in_env = False
                has_run_as_user = False
                has_resource_limits = False
                container_name = ""
                continue

            if re.match(r"^\s*name:\s+", raw) and "metadata:" in raw_lines[max(0, lineno - 5):lineno]:
                name_val = line.split(":", 1)[-1].strip()
                if name_val and current_resource:
                    current_resource = f"{current_resource}/{name_val}"

            if re.match(r"^\s*-?\s*name:\s+", raw) and "containers:" in "\n".join(
                raw_lines[max(0, lineno - 8):lineno]
            ):
                container_name = line.split(":", 1)[-1].strip().strip("'\"")
                if container_name and container_name not in info.containers:
                    info.containers.append(container_name)

            if line == "securityContext:" or line.startswith("securityContext:"):
                in_security_context = True
                in_capabilities = False
                continue

            if in_security_context and line.startswith("capabilities:"):
                in_capabilities = True
                cap_mode = ""
                continue

            if in_capabilities and re.match(r"^\s*add:\s*$", line):
                cap_mode = "add"
                continue

            if in_capabilities and re.match(r"^\s*drop:\s*$", line):
                cap_mode = "drop"
                continue

            if line == "env:" or line.startswith("env:"):
                in_env = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_env and raw and not raw.startswith(" " * (env_indent + 1)):
                in_env = False

            if in_security_context and raw and not raw.startswith(" "):
                in_security_context = False
                in_capabilities = False

            resource_label = container_name or current_resource

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true shares the host network namespace",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if HOST_PID_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares the host PID namespace",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if HOST_IPC_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_ipc",
                        severity="medium",
                        message="hostIPC: true shares the host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if RUN_AS_NON_ROOT_FALSE_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="run_as_non_root_false",
                        severity="high",
                        message="runAsNonRoot: false allows root container execution",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if ALLOW_PRIV_ESC_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="allow_privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true weakens container isolation",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if HOST_PATH_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_path_volume",
                        severity="high",
                        message="hostPath volume mounts host filesystem into the pod",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if in_capabilities and cap_mode == "add" and CAP_ADD_ALL_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="cap_add_all",
                        severity="high",
                        message="capabilities add ALL grants every Linux capability",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if in_env and SECRET_ENV_NAME_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="sensitive env var name — use Secret references instead of literals",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=line,
                    )
                )

            if RUN_AS_USER_PATTERN.match(line):
                has_run_as_user = True

            if RESOURCE_LIMIT_PATTERN.search(line):
                has_resource_limits = True

        if info.containers and not has_resource_limits:
            findings.append(
                KubernetesFinding(
                    kind="no_resource_limits",
                    severity="low",
                    message="no memory/cpu limits detected — set resources.limits",
                    path=rel,
                    lineno=info.lines,
                    resource=info.containers[0] if info.containers else current_resource,
                )
            )

        if info.containers and not has_run_as_user:
            findings.append(
                KubernetesFinding(
                    kind="no_run_as_user",
                    severity="medium",
                    message="no runAsUser in securityContext — container may run as root",
                    path=rel,
                    lineno=info.lines,
                    resource=info.containers[0],
                )
            )

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        infos: list[KubernetesInfo] = []
        paths = self.manifests()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = KubernetesStats(
            manifests=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> KubernetesStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[KubernetesInfo]:
        """Return parsed manifest metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no manifests)."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
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
        """Scaffold a hardened Kubernetes Deployment template."""
        return """\
# Generated by DevAI KubernetesAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          image: python:3.12-slim
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: "1"
              memory: 512Mi
          ports:
            - containerPort: 8000
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes manifests: none found"
        lines = [
            (
                f"Kubernetes manifests: {stats.manifests} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        lines = [
            "# Kubernetes Manifest Audit",
            "",
            self.summary(),
            "",
        ]
        if self.infos:
            lines.append("## Files")
            for info in self.infos:
                kinds = ", ".join(info.kinds) if info.kinds else "unknown"
                lines.append(
                    f"- {info.path}: kinds [{kinds}], "
                    f"{len(info.containers)} container(s)"
                )
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
