"""K8sAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_INLINE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*:\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
ENV_VALUE_SECRET_PATTERN = re.compile(
    r"^\s*value:\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
ALLOW_PRIVILEGE_ESCALATION_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
NO_RESOURCES_PATTERN = re.compile(r"resources:\s*\{\s*\}", re.IGNORECASE)
CAP_SYS_ADMIN_PATTERN = re.compile(r"SYS_ADMIN", re.IGNORECASE)
DEFAULT_NAMESPACE_PATTERN = re.compile(r"namespace:\s*default\b", re.IGNORECASE)
HOST_PATH_MOUNT_PATTERN = re.compile(
    r"path:\s*/(etc|proc|sys|var/run/docker\.sock)",
    re.IGNORECASE,
)
READ_ONLY_ROOT_FALSE_PATTERN = re.compile(r"readOnlyRootFilesystem:\s*false\b", re.IGNORECASE)


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
        res = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{res} — {self.message}"


@dataclass
class K8sInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    resources: list[str] = field(default_factory=list)
    api_version: str = ""
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
    if path.suffix not in (".yaml", ".yml"):
        return False
    name = path.name.lower()
    if name in ("deployment.yaml", "service.yaml", "ingress.yaml", "configmap.yaml", "secret.yaml"):
        return True
    if any(part in path.parts for part in ("k8s", "kubernetes", "manifests", "deploy")):
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:500]
        return "apiVersion:" in text and "kind:" in text
    except OSError:
        return False


class K8sAnalyzer:
    """Audit Kubernetes manifests for privileged pods, host networking, and missing limits."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sInfo] | None = None

    def manifest_files(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
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

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("apiVersion:"):
                info.api_version = line.split(":", 1)[1].strip()

            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                current_resource = kind
                info.resources.append(kind)

            if line.startswith("name:") and current_resource:
                name = line.split(":", 1)[1].strip()
                current_resource = f"{current_resource}/{name}"

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privileged_pod",
                        severity="high",
                        message="Container runs in privileged mode",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="Pod uses host networking",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="Pod uses host PID namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if HOST_IPC_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="host_ipc",
                        severity="high",
                        message="Pod uses host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="run_as_root",
                        severity="high",
                        message="Container runs as root (runAsUser: 0)",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="Container image uses :latest tag",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if SECRET_INLINE_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret in manifest",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if ENV_VALUE_SECRET_PATTERN.search(line) and lineno > 1:
                prev = raw_lines[lineno - 2].strip().lower()
                if "name:" in prev and any(
                    k in prev for k in ("secret", "password", "token", "key", "credential")
                ):
                    findings.append(
                        K8sFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="Hardcoded secret value in env var",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line[:120],
                        )
                    )

            if ALLOW_PRIVILEGE_ESCALATION_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation is true",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if CAP_SYS_ADMIN_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="dangerous_capability",
                        severity="high",
                        message="SYS_ADMIN capability granted",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if HOST_PATH_MOUNT_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="dangerous_hostpath",
                        severity="high",
                        message="Dangerous hostPath mount (sensitive host directory)",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if READ_ONLY_ROOT_FALSE_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="writable_rootfs",
                        severity="medium",
                        message="readOnlyRootFilesystem is false",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if NO_RESOURCES_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="no_resource_limits",
                        severity="low",
                        message="Empty resources block — no CPU/memory limits",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

            if DEFAULT_NAMESPACE_PATTERN.search(line):
                findings.append(
                    K8sFinding(
                        kind="default_namespace",
                        severity="low",
                        message="Resource deployed to default namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line[:120],
                    )
                )

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sInfo] = []
        paths = self.manifest_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
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
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
