"""SkaffoldAnalyzer — audit Skaffold configs for security and Kubernetes dev best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKAFFOLD_FILENAMES = (
    "skaffold.yaml",
    "skaffold.yml",
)
SKAFFOLD_DIRS = ("skaffold", "deploy/skaffold", "k8s/skaffold", "manifests/skaffold")
SKAFFOLD_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*skaffold/",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_BUILD_ARG_PATTERN = re.compile(
    r"^\s*-\s*(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repo|url|chartRepo|oci|repository|base|helmRepo)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|artifactImage|tag)\s*:\s*[\"']?[^\"'\s]*:latest[\"']?\s*$|"
    r"(?:tag|newTag)\s*:\s*[\"']?latest[\"']?\s*$",
    re.IGNORECASE,
)
INSECURE_REGISTRY_PATTERN = re.compile(
    r"^\s*insecureRegistries\s*:\s*$|^\s*-\s*[^#\n]+",
    re.IGNORECASE,
)
SKIP_TLS_PATTERN = re.compile(
    r"(?:insecureSkipTLSVerify|skipTLSVerify|insecure_skip_tls_verify)\s*:\s*true",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"privileged\s*:\s*true",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"hostNetwork\s*:\s*true",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
KUBECTL_FORCE_PATTERN = re.compile(
    r"(?:--force|--grace-period=0|--wait=false|replace:\s*true)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|useClusterAdmin\s*:\s*true",
    re.IGNORECASE,
)
STATUS_CHECK_DISABLED_PATTERN = re.compile(
    r"statusCheck\s*:\s*false",
    re.IGNORECASE,
)
SYNC_SENSITIVE_PATTERN = re.compile(
    r"sync\s*:\s*\n\s+(?:manual|infer)|^\s*-\s*(?:\.env|\.git|/etc|/proc|/sys)",
    re.IGNORECASE | re.MULTILINE,
)
PORT_FORWARD_ALL_PATTERN = re.compile(
    r"portForward\s*:\s*\n|localPort\s*:\s*0\b",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git::)?https?://[^\s\"']+(?![^\n]*(?:ref=|commit=|tag=))",
    re.IGNORECASE,
)
PROD_CONTEXT_PATTERN = re.compile(
    r"kubeContext\s*:\s*[\"']?(?:prod|production|live|staging)[\"']?",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:runAsUser|runAsNonRoot)\s*:\s*(?:0|false)",
    re.IGNORECASE,
)


@dataclass
class SkaffoldFinding:
    """A security or best-practice issue in a Skaffold configuration."""

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
class SkaffoldInfo:
    """Parsed metadata about a Skaffold config file."""

    path: str
    api_version: str = ""
    artifacts: int = 0
    deployers: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class SkaffoldStats:
    """Aggregate Skaffold analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_skaffold_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in SKAFFOLD_FILENAMES:
        return True
    if lower.endswith((".yaml", ".yml")):
        parts = {p.lower() for p in path.parts}
        if parts & set(SKAFFOLD_DIRS):
            return True
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if SKAFFOLD_API_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


class SkaffoldAnalyzer:
    """Audit Skaffold configs for hardcoded secrets, insecure registries, and risky deploy settings.

    Scans ``skaffold.yaml`` for plaintext build args, insecure HTTP/OCI registries, :latest tags,
    kubectl force apply, production kubeContext, disabled status checks, and privileged patches.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SkaffoldFinding] | None = None
        self._stats: SkaffoldStats | None = None
        self._infos: list[SkaffoldInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Skaffold configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_skaffold_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[SkaffoldFinding], SkaffoldInfo]:
        findings: list[SkaffoldFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, SkaffoldInfo(path=rel)

        raw_lines = text.splitlines()
        info = SkaffoldInfo(path=rel, lines=len(raw_lines))

        in_insecure_registries = False
        in_build_args = False
        deployers: list[str] = []
        artifact_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"apiVersion\s*:\s*skaffold/", line, re.IGNORECASE):
                match = re.search(r"skaffold/([\w.]+)", line, re.IGNORECASE)
                if match:
                    info.api_version = match.group(1)

            if re.search(r"^\s*artifacts\s*:\s*$", line, re.IGNORECASE):
                artifact_count += 0  # marker for section

            if re.search(r"^\s*-\s*image\s*:", line, re.IGNORECASE):
                artifact_count += 1

            for deployer in ("kubectl", "helm", "kustomize", "kpt", "docker", "cloudrun"):
                if re.search(rf"^\s*{deployer}\s*:\s*$", line, re.IGNORECASE):
                    deployers.append(deployer)

            if re.search(r"^\s*buildArgs\s*:\s*$", line, re.IGNORECASE):
                in_build_args = True
            elif in_build_args and not line.startswith(" ") and not line.startswith("-"):
                in_build_args = False

            if re.search(r"^\s*insecureRegistries\s*:\s*$", line, re.IGNORECASE):
                in_insecure_registries = True
            elif in_insecure_registries and stripped.startswith("-") and "insecureRegistries" not in line:
                findings.append(
                    SkaffoldFinding(
                        kind="insecure_registry",
                        severity="high",
                        message="insecureRegistries allows unencrypted registry pulls — use TLS-enabled registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif in_insecure_registries and not stripped.startswith("-") and "insecureRegistries" not in line:
                in_insecure_registries = False

            if HARDCODED_SECRET_PATTERN.search(line) or (
                in_build_args and HARDCODED_BUILD_ARG_PATTERN.search(line)
            ):
                findings.append(
                    SkaffoldFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Skaffold config — use secret env files or external secret managers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Skaffold config — use IAM roles or secret references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="insecure HTTP registry or chart repo — use HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a digest or version tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_TLS_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="tls_verification_disabled",
                        severity="high",
                        message="TLS verification disabled for registry or Helm chart fetch",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container enabled — restrict to required workloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork enabled — exposes workload to host network stack",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock mount grants container root on host — avoid in Skaffold builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if KUBECTL_FORCE_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="kubectl_force_apply",
                        severity="high",
                        message="kubectl force/replace deploy can bypass admission controls — use standard apply",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in build script — verify source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="cluster_admin",
                        severity="high",
                        message="cluster-admin or useClusterAdmin grants excessive cluster permissions",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if STATUS_CHECK_DISABLED_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="status_check_disabled",
                        severity="medium",
                        message="statusCheck: false skips rollout verification — enable for production deploys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SYNC_SENSITIVE_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="sensitive_sync_path",
                        severity="medium",
                        message="file sync may expose secrets or host paths — restrict sync paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PORT_FORWARD_ALL_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="broad_port_forward",
                        severity="medium",
                        message="portForward exposes services locally — restrict ports and use namespace isolation",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PROD_CONTEXT_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="production_kube_context",
                        severity="medium",
                        message="kubeContext targets production-like cluster — isolate dev profiles from prod",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    SkaffoldFinding(
                        kind="root_container",
                        severity="medium",
                        message="container runs as root — set runAsNonRoot and non-zero runAsUser",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and "git::" in line.lower():
                if "ref=" not in line and "commit=" not in line and "tag=" not in line:
                    findings.append(
                        SkaffoldFinding(
                            kind="unpinned_git_source",
                            severity="medium",
                            message="git remote source without ref/commit pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        info.artifacts = artifact_count
        info.deployers = deployers
        return findings, info

    def analyze(self) -> list[SkaffoldFinding]:
        """Scan Skaffold configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SkaffoldFinding] = []
        infos: list[SkaffoldInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = SkaffoldStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SkaffoldStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SkaffoldInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened Skaffold configuration."""
        return """\
apiVersion: skaffold/v4beta11
kind: Config
metadata:
  name: app

build:
  artifacts:
    - image: ghcr.io/org/app
      docker:
        dockerfile: Dockerfile
  tagPolicy:
    gitCommit:
      variant: AbbrevCommitSha
  local:
    push: false
    useBuildkit: true

manifests:
  rawYaml:
    - k8s/*.yaml

deploy:
  kubectl:
    flags:
      apply:
        - --server-side
  statusCheck: true
  logs:
    prefix: container

portForward:
  - resourceType: service
    resourceName: app
    namespace: app
    port: 8080
    localPort: 8080
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Skaffold configs: none found"
        return (
            f"Skaffold configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Skaffold analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deployers = ", ".join(info.deployers) if info.deployers else "none"
            lines.append(
                f"  - {info.path}: {info.artifacts} artifact(s), deployers: {deployers}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
