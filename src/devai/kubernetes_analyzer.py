"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_SUFFIXES = (".yaml", ".yml")
MANIFEST_DIR_NAMES = ("kubernetes", "k8s", "manifests", "deploy", "deployment")

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b")
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"]?[^\s'\"#]{4,}",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"^\s*path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
LOAD_BALANCER_PATTERN = re.compile(r"^\s*type:\s*LoadBalancer\b", re.IGNORECASE)
KIND_PATTERN = re.compile(r"^kind:\s*(\w+)", re.IGNORECASE)
API_VERSION_PATTERN = re.compile(r"^apiVersion:\s*(\S+)", re.IGNORECASE)


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
    kinds: list[str] = field(default_factory=list)
    has_security_context: bool = False
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifest_files: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_manifest_file(path: Path) -> bool:
    if path.suffix.lower() not in MANIFEST_SUFFIXES:
        return False
    lower_parts = {part.lower() for part in path.parts}
    if lower_parts & set(MANIFEST_DIR_NAMES):
        return True
    name = path.name.lower()
    if any(token in name for token in ("deployment", "service", "ingress", "configmap", "secret", "statefulset", "daemonset", "cronjob", "job", "namespace", "helm")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:512]
    except OSError:
        return False
    return "apiVersion:" in head and "kind:" in head


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged mode, host namespaces, root containers, secrets in env,
    :latest image tags, dangerous hostPath mounts, and missing security contexts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[KubernetesFinding] | None = None
        self._stats: KubernetesStats | None = None
        self._infos: list[KubernetesInfo] | None = None

    def manifest_files(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_manifest_file(path):
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
        security_context_indent = 0
        doc_has_security_context = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            kind_match = KIND_PATTERN.match(line)
            if kind_match:
                kind = kind_match.group(1)
                info.kinds.append(kind)
                current_resource = kind
                doc_has_security_context = False
                in_security_context = False

            if line.startswith("metadata:") and indent == 0:
                current_resource = ""

            if line.startswith("name:") and indent <= 4 and current_resource:
                name = line.split(":", 1)[1].strip().strip("'\"")
                resource_label = f"{current_resource}/{name}"
                if resource_label not in info.resources:
                    info.resources.append(resource_label)

            if "securityContext:" in line:
                in_security_context = True
                security_context_indent = indent
                doc_has_security_context = True
                info.has_security_context = True
            elif in_security_context and indent <= security_context_indent and not line.endswith(":"):
                in_security_context = False

            def add(kind: str, severity: str, message: str) -> None:
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

            if LATEST_TAG_PATTERN.search(line):
                add(
                    "latest_tag",
                    "medium",
                    "container image uses :latest tag — pin a specific version",
                )

            if PRIVILEGED_PATTERN.match(line):
                add(
                    "privileged",
                    "high",
                    "privileged: true grants excessive container permissions",
                )

            if HOST_NETWORK_PATTERN.match(line):
                add(
                    "host_network",
                    "high",
                    "hostNetwork: true shares the host network namespace",
                )

            if HOST_PID_PATTERN.match(line):
                add(
                    "host_pid",
                    "high",
                    "hostPID: true shares the host process namespace",
                )

            if HOST_IPC_PATTERN.match(line):
                add(
                    "host_ipc",
                    "medium",
                    "hostIPC: true shares the host IPC namespace",
                )

            if RUN_AS_ROOT_PATTERN.match(line):
                add(
                    "run_as_root",
                    "high",
                    "runAsUser: 0 runs the container as root",
                )

            if RUN_AS_NON_ROOT_FALSE_PATTERN.match(line):
                add(
                    "run_as_non_root_false",
                    "high",
                    "runAsNonRoot: false allows root execution",
                )

            if ALLOW_PRIV_ESC_PATTERN.match(line):
                add(
                    "allow_privilege_escalation",
                    "medium",
                    "allowPrivilegeEscalation: true can enable privilege escalation",
                )

            if CAP_ADD_ALL_PATTERN.match(line) and "capabilities" in raw.lower():
                add(
                    "cap_add_all",
                    "high",
                    "capabilities add ALL grants all Linux capabilities",
                )

            if SECRET_ENV_PATTERN.search(line):
                add(
                    "secret_in_env",
                    "high",
                    "potential secret in env — use Secret references instead",
                )

            if HOST_PATH_PATTERN.match(line):
                add(
                    "host_path_mount",
                    "high",
                    "hostPath mount to sensitive host directory",
                )

            if DOCKER_SOCK_PATTERN.search(line):
                add(
                    "docker_sock_mount",
                    "high",
                    "mounting /var/run/docker.sock grants host Docker access",
                )

            if LOAD_BALANCER_PATTERN.match(line):
                add(
                    "load_balancer",
                    "low",
                    "type: LoadBalancer exposes the service publicly — confirm intent",
                )

        if info.kinds and not doc_has_security_context:
            workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}
            if workload_kinds & set(info.kinds):
                findings.append(
                    KubernetesFinding(
                        kind="missing_security_context",
                        severity="medium",
                        message="no securityContext defined for workload — set runAsNonRoot and drop capabilities",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        infos: list[KubernetesInfo] = []
        paths = self.manifest_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        resource_count = sum(len(i.resources) for i in infos)
        self._stats = KubernetesStats(
            manifest_files=len(paths),
            findings=len(findings),
            resources=resource_count,
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
        if stats.manifest_files == 0:
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
  namespace: app
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
          image: ghcr.io/example/app:1.0.0
          imagePullPolicy: IfNotPresent
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
          ports:
            - containerPort: 8080
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifest_files == 0:
            return "Kubernetes manifests: none found"
        return (
            f"Kubernetes manifests: {stats.manifest_files} file(s), "
            f"{stats.resources} resource(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifest files: {stats.manifest_files}",
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.resources)} resource(s), "
                f"kinds={','.join(info.kinds) or 'unknown'}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
