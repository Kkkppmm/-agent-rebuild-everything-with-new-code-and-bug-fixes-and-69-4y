"""KustomizeAnalyzer — audit Kustomize overlays and bases for security misconfigurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

KUSTOMIZE_FILENAMES = (
    "kustomization.yaml",
    "kustomization.yml",
    "kustomize.yaml",
    "kustomize.yml",
)
KUSTOMIZE_DIRS = ("overlays", "bases", "kustomize", "k8s", "kubernetes", "manifests", "deploy")
KUSTOMIZE_API_PATTERN = re.compile(
    r"apiVersion\s*:\s*kustomize\.config\.k8s\.io/",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|repo|base|chartHome|helmGlobals|repoURL)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LOAD_RESTRICTOR_NONE_PATTERN = re.compile(
    r"loadRestrictor\s*:\s*LoadRestrictionsNone",
    re.IGNORECASE,
)
DISABLE_HASH_PATTERN = re.compile(
    r"disableNameSuffixHash\s*:\s*true",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:newName|newTag|name|tag)\s*:\s*[\"']?[^\"'\s]*:latest[\"']?\s*$|"
    r"(?:newTag|tag)\s*:\s*[\"']?latest[\"']?\s*$",
    re.IGNORECASE,
)
EXEC_PLUGIN_PATTERN = re.compile(
    r"^\s*(?:exec|plugin)\s*:\s*$|^\s*path\s*:\s*[\"'][^\"']+[\"']\s*$",
    re.IGNORECASE,
)
GIT_BASE_PATTERN = re.compile(
    r"^\s*-\s*(?:git::)?https?://",
    re.IGNORECASE,
)
GIT_REF_PATTERN = re.compile(
    r"(?:ref|version|tag|commit|branch)\s*[=:]",
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
REMOTE_RESOURCE_PATTERN = re.compile(
    r"^\s*-\s*(?:https?://|git::)",
    re.IGNORECASE,
)
SECRET_LITERAL_PATTERN = re.compile(
    r"^\s*literals\s*:\s*$|^\s*-\s*(?:password|secret|token|api[_-]?key)\s*=",
    re.IGNORECASE,
)
GENERATOR_SECRET_PATTERN = re.compile(
    r"^\s*secretGenerator\s*:\s*$",
    re.IGNORECASE,
)
CONFIGMAP_GENERATOR_PATTERN = re.compile(
    r"^\s*configMapGenerator\s*:\s*$",
    re.IGNORECASE,
)
HELM_CHART_PATTERN = re.compile(
    r"^\s*helmCharts\s*:\s*$",
    re.IGNORECASE,
)
HELM_INSECURE_PATTERN = re.compile(
    r"(?:insecureSkipTLSVerify|skipTLSVerify)\s*:\s*true",
    re.IGNORECASE,
)


@dataclass
class KustomizeFinding:
    """A security or best-practice issue in a Kustomize configuration."""

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
class KustomizeInfo:
    """Parsed metadata about a Kustomize file."""

    path: str
    bases: int = 0
    resources: int = 0
    patches: int = 0
    generators: int = 0
    lines: int = 0


@dataclass
class KustomizeStats:
    """Aggregate Kustomize analysis statistics."""

    overlays: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_kustomize_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in KUSTOMIZE_FILENAMES:
        return True
    if not lower.endswith((".yaml", ".yml")):
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(KUSTOMIZE_DIRS) and lower.startswith("kustom"):
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(KUSTOMIZE_API_PATTERN.search(text))


class KustomizeAnalyzer:
    """Audit Kustomize overlays and bases for hardcoded secrets, insecure remote sources, and risky patches.

    Scans kustomization.yaml files for plaintext credentials in generators, HTTP remote bases,
    disabled load restrictors, exec plugins, unpinned git sources, and privileged patch overrides.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[KustomizeFinding] | None = None
        self._stats: KustomizeStats | None = None
        self._infos: list[KustomizeInfo] | None = None

    def overlays(self) -> list[Path]:
        """Return Kustomize configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_kustomize_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[KustomizeFinding], KustomizeInfo]:
        findings: list[KustomizeFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KustomizeInfo(path=rel)

        info = KustomizeInfo(path=rel, lines=len(raw_lines))
        in_secret_generator = False
        in_configmap_generator = False
        in_helm_charts = False
        in_exec_block = False
        remote_git_line: str | None = None
        remote_git_lineno = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^\s*bases\s*:\s*$", line, re.IGNORECASE):
                pass
            elif re.match(r"^\s*resources\s*:\s*$", line, re.IGNORECASE):
                pass
            elif re.match(r"^\s*patches(?:StrategicMerge|Json6902)?\s*:\s*$", line, re.IGNORECASE):
                info.patches += 1
            elif GENERATOR_SECRET_PATTERN.match(line) or CONFIGMAP_GENERATOR_PATTERN.match(line):
                info.generators += 1
                in_secret_generator = bool(GENERATOR_SECRET_PATTERN.match(line))
                in_configmap_generator = bool(CONFIGMAP_GENERATOR_PATTERN.match(line))
            elif HELM_CHART_PATTERN.match(line):
                in_helm_charts = True
            elif line.startswith("- ") and not line.startswith("- path:"):
                entry = line[2:].strip()
                if entry and not entry.startswith("!") and not entry.startswith("{"):
                    if "://" in entry or entry.startswith("git::"):
                        info.resources += 1
                        if GIT_BASE_PATTERN.match(line):
                            remote_git_line = line
                            remote_git_lineno = lineno
                            if not GIT_REF_PATTERN.search(entry):
                                findings.append(
                                    KustomizeFinding(
                                        kind="unpinned_git_source",
                                        severity="medium",
                                        message="remote git/HTTP base without ref/version pin — pin to a commit or tag",
                                        path=rel,
                                        lineno=lineno,
                                        line=line,
                                    )
                                )
                    elif not entry.startswith("-"):
                        info.bases += 1

            if in_secret_generator and line.startswith("- "):
                in_secret_generator = False
            if in_configmap_generator and line.startswith("- "):
                in_configmap_generator = False
            if in_helm_charts and not line.startswith(" ") and not line.startswith("-"):
                in_helm_charts = False

            if EXEC_PLUGIN_PATTERN.match(line):
                in_exec_block = True
            if in_exec_block and re.match(r"^\s*args\s*:", line, re.IGNORECASE):
                findings.append(
                    KustomizeFinding(
                        kind="exec_plugin",
                        severity="high",
                        message="exec plugin transformer/generator — arbitrary code execution risk",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
                in_exec_block = False

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Kustomize config — use secretGenerator with env files or external secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SECRET_LITERAL_PATTERN.search(line) and (
                in_secret_generator or "literals" in line.lower()
            ):
                findings.append(
                    KustomizeFinding(
                        kind="secret_literal",
                        severity="high",
                        message="plaintext secret in secretGenerator literals — use envs/files or ExternalSecrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) or re.search(
                r"^\s*-\s*http://(?!localhost|127\.0\.0\.1)",
                line,
                re.IGNORECASE,
            ):
                findings.append(
                    KustomizeFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="remote source uses HTTP — fetch bases and charts over HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOAD_RESTRICTOR_NONE_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="load_restrictor_disabled",
                        severity="high",
                        message="loadRestrictor: LoadRestrictionsNone disables path traversal protection",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_HASH_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="hash_suffix_disabled",
                        severity="medium",
                        message="disableNameSuffixHash: true — config/secret updates may not trigger rollouts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image transformer uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="privileged_patch",
                        severity="high",
                        message="patch enables privileged container — remove or restrict to required workloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="host_network_patch",
                        severity="high",
                        message="patch enables hostNetwork — exposes pod to host network stack",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_helm_charts and HELM_INSECURE_PATTERN.search(line):
                findings.append(
                    KustomizeFinding(
                        kind="helm_tls_skip",
                        severity="high",
                        message="Helm chart fetch skips TLS verification — enable certificate validation",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if remote_git_line and "?" not in remote_git_line and "ref=" not in remote_git_line:
            if remote_git_lineno and not any(
                f.lineno == remote_git_lineno and f.kind == "unpinned_git_source" for f in findings
            ):
                findings.append(
                    KustomizeFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="remote git/HTTP base without ref/version pin — pin to a commit or tag",
                        path=rel,
                        lineno=remote_git_lineno,
                        line=remote_git_line,
                    )
                )

        return findings, info

    def analyze(self) -> list[KustomizeFinding]:
        """Scan Kustomize configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KustomizeFinding] = []
        infos: list[KustomizeInfo] = []
        paths = self.overlays()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = KustomizeStats(
            overlays=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> KustomizeStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[KustomizeInfo]:
        """Return parsed overlay metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no overlays)."""
        self.analyze()
        stats = self.stats
        if stats.overlays == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_overlay(self) -> str:
        """Scaffold a hardened Kustomize overlay."""
        return """\
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: app

resources:
  - ../../base

commonLabels:
  app.kubernetes.io/managed-by: kustomize

images:
  - name: ghcr.io/org/app
    newTag: v1.0.0

patches:
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: app
      spec:
        template:
          spec:
            securityContext:
              runAsNonRoot: true
            containers:
              - name: app
                securityContext:
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
    target:
      kind: Deployment
      name: app
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.overlays == 0:
            return "Kustomize overlays: none found"
        return (
            f"Kustomize overlays: {stats.overlays} overlay(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kustomize analysis:",
            f"  overlays: {stats.overlays}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {info.bases} base(s), {info.resources} resource(s), "
                f"{info.generators} generator(s)"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
