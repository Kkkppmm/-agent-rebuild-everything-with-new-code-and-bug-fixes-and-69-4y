"""K8sAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIRS = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm")
K8S_KIND_PATTERN = re.compile(r"^kind:\s*(\w+)", re.IGNORECASE)
API_VERSION_PATTERN = re.compile(r"^apiVersion:\s*", re.IGNORECASE)

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
HOST_PATH_PATTERN = re.compile(r"hostPath:\s*$|path:\s*['\"]?(?:/etc|/var/run|/proc|/sys)", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*:\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
ALLOW_PRIVILEGE_ESCALATION_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
CAP_SYS_ADMIN_PATTERN = re.compile(r"SYS_ADMIN|NET_ADMIN|ALL", re.IGNORECASE)


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
        resource = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{resource} — {self.message}"


@dataclass
class K8sInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    resources: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
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
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(K8S_DIRS):
        return True
    name = path.name.lower()
    if any(token in name for token in ("deployment", "service", "ingress", "configmap", "secret", "pod", "statefulset")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    except OSError:
        return False
    return bool(API_VERSION_PATTERN.search(head) and K8S_KIND_PATTERN.search(head))


class K8sAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged containers, host namespaces, root users, hostPath mounts,
    latest image tags, hardcoded secrets in env, and excessive capabilities.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[K8sFinding], K8sInfo]:
        findings: list[K8sFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, K8sInfo(path=rel)

        info = K8sInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        current_kind = ""
        pending_env_name = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            kind_match = K8S_KIND_PATTERN.match(line)
            if kind_match:
                current_kind = kind_match.group(1)
                info.kinds.append(current_kind)

            if line.startswith("name:") and current_kind:
                name = line.split(":", 1)[1].strip()
                current_resource = f"{current_kind}/{name}"
                info.resources.append(current_resource)

            if line.startswith("---"):
                current_resource = ""
                current_kind = ""
                pending_env_name = ""
                continue

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged container enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true shares the host network namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares the host process namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="medium",
                        message="runAsUser: 0 runs container as root — use a non-root user",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if HOST_PATH_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_path",
                        severity="high",
                        message="hostPath volume can expose host filesystem — restrict paths",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="latest_image",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            env_name_match = re.match(r"-\s*name:\s*(\S+)", line)
            if env_name_match:
                pending_env_name = env_name_match.group(1)

            if line.startswith("value:") and pending_env_name:
                value = line.split(":", 1)[1].strip().strip("'\"")
                if value and "secretKeyRef" not in raw and "valueFrom" not in raw:
                    if re.search(
                        r"(password|secret|api[_-]?key|token|credential)",
                        pending_env_name,
                        re.IGNORECASE,
                    ):
                        findings.append(
                            K8sFinding(
                                kind="secret_in_env",
                                severity="high",
                                message="potential secret hardcoded in env — use Kubernetes Secrets",
                                path=rel,
                                lineno=lineno,
                                resource=current_resource,
                                line=raw.strip(),
                            )
                        )
                pending_env_name = ""

            if SECRET_ENV_PATTERN.search(line) and "secretKeyRef" not in line:
                findings.append(
                    K8sFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="potential secret hardcoded in env — use Kubernetes Secrets",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIVILEGE_ESCALATION_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true — set to false when possible",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=raw.strip(),
                    )
                )

            if "capabilities:" in line.lower() or "add:" in line:
                if CAP_SYS_ADMIN_PATTERN.search(line):
                    findings.append(
                        K8sFinding(
                            kind="dangerous_capability",
                            severity="high",
                            message="dangerous Linux capability granted — drop unnecessary caps",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=raw.strip(),
                        )
                    )

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sInfo] = []
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[K8sInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.manifests == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        return """\
# Generated by DevAI K8sAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
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
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          image: myregistry/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            limits:
              memory: "256Mi"
              cpu: "500m"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: none found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifests: {stats.manifests}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            kinds = ", ".join(info.kinds[:5]) or "unknown"
            lines.append(f"  - {info.path}: {len(info.resources)} resource(s), kinds=[{kinds}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
