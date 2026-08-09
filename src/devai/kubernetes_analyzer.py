"""KubernetesAnalyzer — audit K8s manifests for security and deployment best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIR_NAMES = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm")
K8S_SUFFIXES = (".yaml", ".yml")

PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"^\s*-\s*path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(resources:\s*$|limits:\s*$|requests:\s*$|memory:\s*|cpu:\s*)",
    re.IGNORECASE,
)
RUN_AS_NON_ROOT_PATTERN = re.compile(r"^\s*runAsNonRoot:\s*true\b", re.IGNORECASE)
DROP_ALL_CAPS_PATTERN = re.compile(r"drop:\s*\n\s*-\s*ALL\b", re.IGNORECASE | re.MULTILINE)
READ_ONLY_ROOT_PATTERN = re.compile(r"^\s*readOnlyRootFilesystem:\s*true\b", re.IGNORECASE)


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
    containers: int = 0
    has_resource_limits: bool = False
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_kubernetes_file(path: Path) -> bool:
    if path.suffix.lower() not in K8S_SUFFIXES:
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(K8S_DIR_NAMES):
        return True
    name = path.name.lower()
    if any(token in name for token in ("deployment", "service", "ingress", "configmap", "secret", "statefulset", "daemonset", "cronjob", "job", "pod", "namespace", "helm")):
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged mode, host namespaces, root execution, secrets in env,
    :latest image tags, sensitive hostPath mounts, and missing resource limits.
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
            if path.is_file() and _is_kubernetes_file(path):
                found.append(path)
        return found

    def _current_resource(self, line: str, current: str) -> str:
        stripped = line.strip()
        if stripped.startswith("kind:"):
            return stripped.split(":", 1)[1].strip()
        if stripped.startswith("name:") and current:
            return f"{current}/{stripped.split(':', 1)[1].strip()}"
        return current

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        resource = ""
        in_container = False
        has_limits_nearby = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line.strip():
                continue

            if line.strip().startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                info.kinds.append(kind)
                resource = kind

            if line.strip().startswith("name:") and resource:
                name = line.split(":", 1)[1].strip()
                resource = f"{resource}/{name}"

            if re.match(r"^\s*containers:\s*$", line, re.IGNORECASE):
                in_container = True
            if re.match(r"^\s*-\s*name:\s+", line) and in_container:
                info.containers += 1

            if RESOURCE_LIMIT_PATTERN.search(line):
                info.has_resource_limits = True
                has_limits_nearby = True

            checks = [
                (PRIVILEGED_PATTERN, "privileged", "high", "privileged: true grants full host access"),
                (HOST_NETWORK_PATTERN, "host_network", "high", "hostNetwork: true bypasses network isolation"),
                (HOST_PID_PATTERN, "host_pid", "high", "hostPID: true shares host process namespace"),
                (HOST_IPC_PATTERN, "host_ipc", "medium", "hostIPC: true shares host IPC namespace"),
                (RUN_AS_ROOT_PATTERN, "run_as_root", "high", "runAsUser: 0 runs container as root"),
                (ALLOW_PRIV_ESC_PATTERN, "allow_priv_esc", "medium", "allowPrivilegeEscalation: true without dropped caps"),
                (LATEST_TAG_PATTERN, "latest_tag", "medium", "image uses :latest — pin to a specific digest or version"),
                (HOST_PATH_PATTERN, "host_path", "high", "hostPath mount to sensitive host directory"),
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
                            resource=resource,
                            line=raw.strip(),
                        )
                    )

            if SECRET_ENV_PATTERN.search(line) and ("value:" in line.lower() or "env:" in line.lower() or "=" in line):
                findings.append(
                    KubernetesFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="potential secret in env — use Kubernetes Secrets or external secret managers",
                        path=rel,
                        lineno=lineno,
                        resource=resource,
                        line=raw.strip(),
                    )
                )

        if info.containers > 0 and not info.has_resource_limits:
            findings.append(
                KubernetesFinding(
                    kind="missing_resource_limits",
                    severity="medium",
                    message="no resource limits/requests defined for containers",
                    path=rel,
                    lineno=1,
                    resource=resource,
                    line="",
                )
            )

        if info.containers > 0 and not any(READ_ONLY_ROOT_PATTERN.search(_strip_comment(l)) for l in raw_lines):
            findings.append(
                KubernetesFinding(
                    kind="writable_root_fs",
                    severity="low",
                    message="consider readOnlyRootFilesystem: true for immutable containers",
                    path=rel,
                    lineno=1,
                    resource=resource,
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
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8000
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
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes manifests: none found"
        return (
            f"Kubernetes manifests: {stats.manifests} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            self.summary(),
            f"Health score: {self.health_score()}/100",
        ]
        if self._findings:
            lines.append("")
            lines.append("Findings:")
            for finding in self._findings[:50]:
                lines.append(f"  - {finding.format()}")
            if len(self._findings) > 50:
                lines.append(f"  ... and {len(self._findings) - 50} more")
        return "\n".join(lines)
