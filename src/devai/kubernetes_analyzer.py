"""K8sAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_DIRS = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm")
YAML_SUFFIXES = (".yml", ".yaml")

LATEST_IMAGE_PATTERN = re.compile(r"^\s*image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b|^\s*runAsUser:\s*0\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"^\s*-\s*path:\s*['\"]?(?:/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)


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
class K8sResourceInfo:
    """Parsed metadata about a Kubernetes resource."""

    kind: str
    name: str


@dataclass
class K8sManifestInfo:
    """Parsed metadata about a Kubernetes manifest file."""

    path: str
    resources: list[K8sResourceInfo] = field(default_factory=list)
    lines: int = 0


@dataclass
class K8sStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in YAML_SUFFIXES:
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(MANIFEST_DIRS):
        return True
    name = path.name.lower()
    return any(
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
        )
    )


class K8sAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged containers, host networking, :latest images,
    hostPath mounts to sensitive paths, secrets in env literals, and
    missing security context hardening.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sManifestInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
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
        current_kind = ""
        current_name = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = re.match(r"^kind:\s*(\S+)", line, re.IGNORECASE)
            if kind_match:
                current_kind = kind_match.group(1)

            name_match = re.match(r"^name:\s*(\S+)", line, re.IGNORECASE)
            if name_match and current_kind:
                current_name = name_match.group(1)
                info.resources.append(K8sResourceInfo(kind=current_kind, name=current_name))

            resource_label = f"{current_kind}/{current_name}" if current_kind else ""

            if LATEST_IMAGE_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="latest_image",
                        severity="medium",
                        message="container image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access to the container",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true shares the host network namespace",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true exposes host process namespace",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if HOST_IPC_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_ipc",
                        severity="medium",
                        message="hostIPC: true shares host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="high",
                        message="container configured to run as root — set runAsNonRoot: true",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIV_ESC_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true — set to false unless required",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if HOST_PATH_PATTERN.match(line):
                findings.append(
                    K8sFinding(
                        kind="host_path_mount",
                        severity="high",
                        message="hostPath mount to sensitive host path detected",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

            if SECRET_ENV_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="secret hardcoded in env — use Kubernetes Secrets",
                        path=rel,
                        lineno=lineno,
                        resource=resource_label,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sManifestInfo] = []
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
        self._stats = K8sStats(
            manifests=len(paths),
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
        """Return a 0-100 health score."""
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
# Generated by DevAI K8sAnalyzer
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
          image: myapp:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              memory: "512Mi"
              cpu: "500m"
            requests:
              memory: "128Mi"
              cpu: "100m"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: no manifests found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), "
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
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.resources)} resource(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
