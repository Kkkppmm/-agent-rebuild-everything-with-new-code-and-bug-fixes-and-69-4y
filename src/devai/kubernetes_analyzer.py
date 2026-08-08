"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_EXTENSIONS = (".yaml", ".yml")
K8S_DIR_NAMES = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm")

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b")
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
HOST_PATH_SENSITIVE_PATTERN = re.compile(
    r"^\s*path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
HOST_PATH_TYPE_PATTERN = re.compile(r"^\s*hostPath:\s*$", re.IGNORECASE)
SECRET_KEY_REF_PATTERN = re.compile(r"secretKeyRef:", re.IGNORECASE)
LATEST_CHART_PATTERN = re.compile(r"version:\s*['\"]?latest['\"]?", re.IGNORECASE)


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
    resources: list[str] = field(default_factory=list)
    has_security_context: bool = False
    has_resource_limits: bool = False
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in K8S_EXTENSIONS:
        return False
    lower_parts = {p.lower() for p in path.parts}
    if lower_parts & set(K8S_DIR_NAMES):
        return True
    name = path.name.lower()
    if any(
        token in name
        for token in (
            "deployment",
            "service",
            "ingress",
            "configmap",
            "secret",
            "statefulset",
            "daemonset",
            "cronjob",
            "job",
            "pod",
            "namespace",
            "helm",
            "k8s",
            "kube",
        )
    ):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    except OSError:
        return False
    return bool(
        re.search(r"^\s*apiVersion:\s*", head, re.MULTILINE)
        and re.search(r"^\s*kind:\s*", head, re.MULTILINE)
    )


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged mode, host namespaces, root containers, secrets in
    plain env, :latest image tags, sensitive hostPath mounts, and missing
    security contexts.
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
        in_container_spec = False
        container_has_security = False
        doc_has_security = False
        in_env_block = False
        env_indent = 0
        in_host_path = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                current_resource = kind
                if kind not in info.resources:
                    info.resources.append(kind)
                in_container_spec = False
                container_has_security = False
                doc_has_security = False
                continue

            if line.startswith("metadata:") and current_resource:
                name = ""
                for peek in raw_lines[lineno : min(lineno + 10, len(raw_lines))]:
                    peek_line = peek.strip()
                    if peek_line.startswith("name:"):
                        name = peek_line.split(":", 1)[1].strip()
                        break
                if name:
                    current_resource = f"{current_resource}/{name}"

            if line in ("containers:", "initContainers:"):
                in_container_spec = True
                container_has_security = False
                continue

            if in_container_spec and line == "securityContext:":
                container_has_security = True
                in_security_context = True
                doc_has_security = True
                info.has_security_context = True
                continue

            if line == "securityContext:" and not in_container_spec:
                in_security_context = True
                doc_has_security = True
                info.has_security_context = True
                continue

            if in_security_context and indent <= 4 and not line.startswith("securityContext"):
                in_security_context = False

            if line.startswith("resources:") or re.search(
                r"(limits|requests):\s*$", line, re.IGNORECASE
            ):
                info.has_resource_limits = True

            if line.startswith("env:"):
                in_env_block = True
                env_indent = indent
                continue

            if in_env_block:
                if indent <= env_indent and not line.startswith("-") and "value:" not in line:
                    in_env_block = False
                elif SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        KubernetesFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="possible secret in plain env value — use secretKeyRef",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

            if HOST_PATH_TYPE_PATTERN.match(line):
                in_host_path = True
                continue

            if in_host_path and HOST_PATH_SENSITIVE_PATTERN.match(line):
                findings.append(
                    KubernetesFinding(
                        kind="sensitive_hostpath",
                        severity="high",
                        message="hostPath mount to sensitive host path",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )
                in_host_path = False

            if indent <= 4 and not line.startswith("path:"):
                in_host_path = False

            checks = [
                (PRIVILEGED_PATTERN, "privileged", "high", "privileged: true — avoid privileged pods"),
                (HOST_NETWORK_PATTERN, "host_network", "high", "hostNetwork: true exposes host network stack"),
                (HOST_PID_PATTERN, "host_pid", "high", "hostPID: true shares host process namespace"),
                (HOST_IPC_PATTERN, "host_ipc", "medium", "hostIPC: true shares host IPC namespace"),
                (RUN_AS_ROOT_PATTERN, "run_as_root", "high", "runAsUser: 0 — run containers as non-root"),
                (
                    ALLOW_PRIV_ESC_PATTERN,
                    "allow_privilege_escalation",
                    "medium",
                    "allowPrivilegeEscalation: true — set to false when possible",
                ),
                (
                    LATEST_TAG_PATTERN,
                    "latest_tag",
                    "medium",
                    "image uses :latest tag — pin a specific version",
                ),
                (
                    LATEST_CHART_PATTERN,
                    "latest_chart",
                    "low",
                    "Helm chart version set to latest — pin chart versions",
                ),
            ]

            for pattern, kind, severity, message in checks:
                if pattern.search(line):
                    findings.append(
                        KubernetesFinding(
                            kind=kind,
                            severity=severity,
                            message=message,
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

            if CAP_ADD_ALL_PATTERN.match(line) and "capabilities" in raw_lines[max(0, lineno - 5) : lineno]:
                findings.append(
                    KubernetesFinding(
                        kind="cap_add_all",
                        severity="high",
                        message="capabilities add ALL — drop unnecessary capabilities",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

        workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}
        if any(r.split("/")[0] in workload_kinds for r in info.resources) and not doc_has_security:
            findings.append(
                KubernetesFinding(
                    kind="missing_security_context",
                    severity="medium",
                    message="workload has no securityContext — set runAsNonRoot and readOnlyRootFilesystem",
                    path=rel,
                    lineno=0,
                    resource=current_resource,
                )
            )

        if any(r.split("/")[0] in workload_kinds for r in info.resources) and not info.has_resource_limits:
            findings.append(
                KubernetesFinding(
                    kind="no_resource_limits",
                    severity="low",
                    message="no CPU/memory limits — set resources.requests and resources.limits",
                    path=rel,
                    lineno=0,
                    resource=current_resource,
                )
            )

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        infos: list[KubernetesInfo] = []
        paths = self.manifests()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_resources = sum(len(i.resources) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = KubernetesStats(
            manifests=len(paths),
            findings=len(findings),
            resources=total_resources,
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
  labels:
    app: app
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
          image: ghcr.io/org/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: api-key
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: no manifests found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), {stats.resources} resource(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifests: {stats.manifests}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            resource_list = ", ".join(info.resources[:8]) or "none"
            lines.append(f"  - {info.path}: [{resource_list}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
