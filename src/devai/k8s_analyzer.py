"""K8sAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIR_NAMES = {"k8s", "kubernetes", "manifests", "deploy", "deployment", "helm"}
K8S_FILE_SUFFIXES = (".yaml", ".yml")
K8S_FILE_HINTS = (
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
    "networkpolicy",
    "rolebinding",
    "clusterrole",
)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
READ_ONLY_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*readOnlyRootFilesystem:\s*false\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
HOST_PATH_SENSITIVE_PATTERN = re.compile(
    r"path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run)['\"]?",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
SECRET_LITERAL_PATTERN = re.compile(
    r"^\s*-\s*name:\s*\w*(password|secret|token|key)\w*",
    re.IGNORECASE,
)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(limits:|requests:|cpu:|memory:)",
    re.IGNORECASE,
)
SECURITY_CONTEXT_PATTERN = re.compile(r"^\s*securityContext:\s*$", re.IGNORECASE)
RUN_AS_USER_PATTERN = re.compile(r"^\s*runAsUser:\s+", re.IGNORECASE)
AUTOMOUNT_TOKEN_TRUE_PATTERN = re.compile(
    r"^\s*automountServiceAccountToken:\s*true\b",
    re.IGNORECASE,
)
HOST_PATH_TYPE_PATTERN = re.compile(r"^\s*hostPath:\s*$", re.IGNORECASE)
K8S_MARKER_PATTERN = re.compile(r"^\s*(apiVersion|kind):\s+", re.IGNORECASE)


@dataclass
class K8sFinding:
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
class K8sManifestInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class K8sStats:
    """Aggregate Kubernetes analysis statistics."""

    manifest_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_file(path: Path) -> bool:
    if path.suffix.lower() not in K8S_FILE_SUFFIXES:
        return False
    name_lower = path.name.lower()
    if any(hint in name_lower for hint in K8S_FILE_HINTS):
        return True
    parts = {part.lower() for part in path.parts}
    if parts & K8S_DIR_NAMES:
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    except OSError:
        return False
    return bool(K8S_MARKER_PATTERN.search(head))


class K8sAnalyzer:
    """Audit Kubernetes manifests for security risks and cluster best practices.

    Scans for privileged pods, host namespaces, secrets in env literals,
    dangerous hostPath mounts, :latest image tags, missing resource limits,
    and weak securityContext settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sManifestInfo] | None = None

    def manifest_files(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[K8sFinding], K8sManifestInfo]:
        findings: list[K8sFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, K8sManifestInfo(path=rel)

        info = K8sManifestInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        current_kind = ""
        in_containers = False
        container_indent = 0
        container_has_security = False
        container_has_resources = False
        container_has_run_as_user = False
        in_env = False
        env_indent = 0
        in_capabilities = False
        cap_indent = 0
        doc_has_resource_limits = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            kind_match = re.match(r"^kind:\s*(\S+)", line, re.IGNORECASE)
            if kind_match:
                current_kind = kind_match.group(1)
                if current_kind not in info.kinds:
                    info.kinds.append(current_kind)

            name_match = re.match(r"^name:\s*(\S+)", line, re.IGNORECASE)
            if name_match and indent <= 4:
                current_resource = name_match.group(1).strip("'\"")
                if current_resource not in info.resources:
                    info.resources.append(current_resource)

            if line == "containers:" or line.startswith("containers:"):
                in_containers = True
                container_indent = indent
                container_has_security = False
                container_has_resources = False
                container_has_run_as_user = False
                in_env = False
                in_capabilities = False
                continue

            if in_containers and indent <= container_indent and not line.startswith("-"):
                if current_kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
                    if not container_has_security:
                        findings.append(
                            K8sFinding(
                                kind="no_security_context",
                                severity="medium",
                                message=(
                                    "container has no securityContext — "
                                    "set runAsNonRoot and readOnlyRootFilesystem"
                                ),
                                path=rel,
                                lineno=lineno,
                                resource=current_resource,
                            )
                        )
                    elif not container_has_run_as_user:
                        findings.append(
                            K8sFinding(
                                kind="no_run_as_user",
                                severity="low",
                                message="securityContext missing runAsUser — pin a non-root UID",
                                path=rel,
                                lineno=lineno,
                                resource=current_resource,
                            )
                        )
                    if not container_has_resources and not doc_has_resource_limits:
                        findings.append(
                            K8sFinding(
                                kind="no_resource_limits",
                                severity="low",
                                message="no CPU/memory limits — set resources.limits",
                                path=rel,
                                lineno=lineno,
                                resource=current_resource,
                            )
                        )
                in_containers = False

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access to the pod",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true bypasses pod network isolation",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares the host PID namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_IPC_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_ipc",
                        severity="high",
                        message="hostIPC: true shares the host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIV_ESC_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="allow_privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true weakens container isolation",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.match(line) or RUN_AS_NON_ROOT_FALSE_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="high",
                        message="container configured to run as root",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if READ_ONLY_ROOT_FALSE_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="writable_root_fs",
                        severity="medium",
                        message="readOnlyRootFilesystem: false allows runtime filesystem writes",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="mounting /var/run/docker.sock grants host Docker API access",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PATH_SENSITIVE_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="sensitive_host_path",
                        severity="high",
                        message="hostPath references a sensitive host directory",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if AUTOMOUNT_TOKEN_TRUE_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="automount_service_token",
                        severity="medium",
                        message=(
                            "automountServiceAccountToken: true — "
                            "disable unless the pod needs API access"
                        ),
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PATH_TYPE_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_path_volume",
                        severity="medium",
                        message="hostPath volume exposes host filesystem to the pod",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if line == "env:" or line.startswith("env:"):
                in_env = True
                env_indent = indent
                continue

            if in_env:
                child_indent = len(raw) - len(raw.lstrip())
                if child_indent <= env_indent and line.endswith(":"):
                    in_env = False
                elif SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        K8sFinding(
                            kind="secret_in_env",
                            severity="high",
                            message=(
                                "potential secret in env — "
                                "use Kubernetes Secrets with secretKeyRef"
                            ),
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )
                elif SECRET_LITERAL_PATTERN.match(line):
                    findings.append(
                        K8sFinding(
                            kind="secret_env_name",
                            severity="medium",
                            message="sensitive env var name — prefer secretKeyRef over literals",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

            if line == "capabilities:" or line.startswith("capabilities:"):
                in_capabilities = True
                cap_indent = indent
                continue

            if in_capabilities:
                child_indent = len(raw) - len(raw.lstrip())
                if child_indent <= cap_indent and line.endswith(":"):
                    in_capabilities = False
                elif CAP_ADD_ALL_PATTERN.match(line):
                    findings.append(
                        K8sFinding(
                            kind="cap_add_all",
                            severity="high",
                            message="capabilities add ALL grants every Linux capability",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

            if SECURITY_CONTEXT_PATTERN.match(line):
                container_has_security = True

            if RUN_AS_USER_PATTERN.match(line):
                container_has_run_as_user = True

            if RESOURCE_LIMIT_PATTERN.search(line):
                container_has_resources = True
                doc_has_resource_limits = True

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sManifestInfo] = []
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
        self._stats = K8sStats(
            manifest_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> K8sStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[K8sManifestInfo]:
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
# Generated by DevAI K8sAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels:
    app: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: python:3.12-slim@sha256:REPLACE_WITH_DIGEST
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          ports:
            - containerPort: 8000
              name: http
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifest_files == 0:
            return "Kubernetes manifests: none found"
        lines = [
            (
                f"Kubernetes manifests: {stats.manifest_files} file(s), "
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
                lines.append(f"- {info.path}: kind(s) [{kinds}]")
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
