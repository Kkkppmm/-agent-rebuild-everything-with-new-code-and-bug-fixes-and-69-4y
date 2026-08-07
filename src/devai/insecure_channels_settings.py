"""InsecureChannelsSettingsAnalyzer — detect insecure Django Channels configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PROD_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "channels.py",
        "asgi.py",
    }
)
_IN_MEMORY_LAYER_RE = re.compile(
    r"channels\.layers\.InMemoryChannelLayer|InMemoryChannelLayer",
    re.IGNORECASE,
)
_REDIS_NO_AUTH_RE = re.compile(
    r"redis://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_CHANNEL_LAYERS_RE = re.compile(r"CHANNEL_LAYERS", re.IGNORECASE)
_WEAK_ENCRYPTION_KEY_RE = re.compile(
    r"symmetric_encryption_keys|SECRET_KEY|django-insecure|['\"]secret['\"]|['\"]changeme['\"]",
    re.IGNORECASE,
)
_WILDCARD_HOST_RE = re.compile(
    r"hosts\s*[:=]\s*\[.*['\"]?\*['\"]?|0\.0\.0\.0",
    re.IGNORECASE,
)


@dataclass
class InsecureChannelsSettingsFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""

    def format(self) -> str:
        setting = f" ({self.setting})" if self.setting else ""
        return f"{self.path}:{self.lineno}{setting} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureChannelsSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _redis_has_no_auth(value: str) -> bool:
    if "redis://" not in value.lower():
        return False
    return bool(_REDIS_NO_AUTH_RE.search(value))


def _is_weak_encryption_key(value: str) -> bool:
    lower = value.lower().strip()
    if not lower:
        return True
    weak = {"secret", "changeme", "django-insecure", "password", "test", "default"}
    return lower in weak or "django-insecure" in lower


class _InsecureChannelsSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureChannelsSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureChannelsSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "CHANNEL_LAYERS":
                self._scan_channel_layers(node.lineno, node.value)
        self.generic_visit(node)

    def _scan_channel_layers(self, lineno: int, node: ast.AST) -> None:
        if not isinstance(node, ast.Dict):
            return
        for key, value in zip(node.keys, node.values):
            key_str = _dict_string_value(key) if key is not None else None
            if key_str != "default":
                continue
            if not isinstance(value, ast.Dict):
                continue
            backend = None
            config = None
            for cfg_key, cfg_val in zip(value.keys, value.values):
                cfg_key_str = _dict_string_value(cfg_key) if cfg_key is not None else None
                if cfg_key_str == "BACKEND":
                    backend = _dict_string_value(cfg_val)
                elif cfg_key_str == "CONFIG":
                    config = cfg_val
            if backend and "inmemorychannellayer" in backend.lower().replace("_", ""):
                self._add(
                    lineno,
                    "in_memory_channel_layer",
                    "high",
                    "InMemoryChannelLayer is not suitable for production — use Redis or another shared backend",
                    setting="CHANNEL_LAYERS",
                )
            if config is not None and isinstance(config, ast.Dict):
                self._scan_channel_config(lineno, config)

    def _scan_channel_config(self, lineno: int, config: ast.Dict) -> None:
        for cfg_key, cfg_val in zip(config.keys, config.values):
            cfg_key_str = _dict_string_value(cfg_key) if cfg_key is not None else None
            if cfg_key_str == "hosts" and isinstance(cfg_val, ast.List):
                for host in cfg_val.elts:
                    host_str = _dict_string_value(host)
                    if host_str and _redis_has_no_auth(host_str):
                        self._add(
                            lineno,
                            "unauthenticated_redis_channel_layer",
                            "high",
                            "Channel layer Redis host has no authentication — secure the connection",
                            setting="CHANNEL_LAYERS",
                        )
            if cfg_key_str == "symmetric_encryption_keys" and isinstance(cfg_val, ast.List):
                for key_node in cfg_val.elts:
                    key_str = _dict_string_value(key_node)
                    if key_str and _is_weak_encryption_key(key_str):
                        self._add(
                            lineno,
                            "weak_channel_encryption_key",
                            "critical",
                            "Channel layer uses a weak symmetric encryption key — use a strong random secret",
                            setting="symmetric_encryption_keys",
                        )


class InsecureChannelsSettingsAnalyzer:
    """Detect insecure Django Channels configuration in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureChannelsSettingsFinding] = []
        self._stats: InsecureChannelsSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureChannelsSettingsFinding]:
        findings: list[InsecureChannelsSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureChannelsSettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _IN_MEMORY_LAYER_RE.search(line) and _CHANNEL_LAYERS_RE.search(source):
                findings.append(
                    InsecureChannelsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="in_memory_channel_layer",
                        severity="high",
                        message="InMemoryChannelLayer is not suitable for production",
                        setting="CHANNEL_LAYERS",
                    )
                )
            if _CHANNEL_LAYERS_RE.search(line) and _REDIS_NO_AUTH_RE.search(line):
                findings.append(
                    InsecureChannelsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="unauthenticated_redis_channel_layer",
                        severity="high",
                        message="Channel layer uses Redis without authentication",
                    )
                )
            if _WILDCARD_HOST_RE.search(line) and _CHANNEL_LAYERS_RE.search(source):
                findings.append(
                    InsecureChannelsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="wildcard_channel_hosts",
                        severity="medium",
                        message="Channel layer hosts allow wildcard or 0.0.0.0 binding — restrict to trusted hosts",
                    )
                )
            if _WEAK_ENCRYPTION_KEY_RE.search(line) and "symmetric_encryption" in line.lower():
                if re.search(r"['\"](secret|changeme|django-insecure|password|test)['\"]", line, re.I):
                    findings.append(
                        InsecureChannelsSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="weak_channel_encryption_key",
                            severity="critical",
                            message="Channel layer uses a weak symmetric encryption key",
                            setting="symmetric_encryption_keys",
                        )
                    )
        return findings

    def analyze(self) -> list[InsecureChannelsSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureChannelsSettingsFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source, path.name)
            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureChannelsSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureChannelsSettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 35.0 + high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure Channels settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Channels settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Channels configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
