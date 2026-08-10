"""InsecureCacheSettingsAnalyzer — detect insecure cache configuration."""

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
        "cache.py",
    }
)
_LOCMEM_BACKEND_RE = re.compile(
    r"(django\.core\.cache\.backends\.)?locmem\.LocMemCache|LocMemCache",
    re.IGNORECASE,
)
_DUMMY_BACKEND_RE = re.compile(
    r"(django\.core\.cache\.backends\.)?dummy\.DummyCache|DummyCache",
    re.IGNORECASE,
)
_REDIS_NO_AUTH_RE = re.compile(
    r"redis://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_MEMCACHED_PLAIN_RE = re.compile(
    r"memcached://[^\s\"']+|['\"]127\.0\.0\.1:11211['\"]|['\"]localhost:11211['\"]",
    re.IGNORECASE,
)
@dataclass
class InsecureCacheSettingsFinding:
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
class InsecureCacheSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_locmem_backend(value: str) -> bool:
    return bool(_LOCMEM_BACKEND_RE.search(value))


def _is_dummy_backend(value: str) -> bool:
    return bool(_DUMMY_BACKEND_RE.search(value))


def _redis_has_no_auth(value: str) -> bool:
    if "redis://" not in value.lower():
        return False
    return bool(_REDIS_NO_AUTH_RE.search(value))


class _InsecureCacheSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureCacheSettingsFinding] = []
        self._in_caches = False

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureCacheSettingsFinding(
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
            if isinstance(target, ast.Name) and target.id == "CACHES":
                if isinstance(node.value, ast.Dict):
                    self._scan_caches_dict(node.value)
        self.generic_visit(node)

    def _scan_caches_dict(self, node: ast.Dict) -> None:
        for cache_key, cache_config in zip(node.keys, node.values):
            if not isinstance(cache_config, ast.Dict):
                continue
            cache_name = _dict_string_value(cache_key) if cache_key else "default"
            if cache_name is None and isinstance(cache_key, ast.Constant):
                cache_name = str(cache_key.value)
            cache_name = cache_name or "default"

            for key_node, value_node in zip(cache_config.keys, cache_config.values):
                key = _dict_string_value(key_node) if key_node else None
                if key is None:
                    continue
                value = _dict_string_value(value_node)
                if key.upper() == "BACKEND" and value:
                    if _is_locmem_backend(value) and self.filename in _PROD_FILENAMES:
                        self._add(
                            cache_config.lineno,
                            "locmem_cache_in_production",
                            "high",
                            "LocMemCache is not shared across processes — use Redis or Memcached",
                            setting=f"CACHES['{cache_name}'].BACKEND",
                        )
                    elif _is_dummy_backend(value) and self.filename in _PROD_FILENAMES:
                        self._add(
                            cache_config.lineno,
                            "dummy_cache_in_production",
                            "medium",
                            "DummyCache disables caching entirely — use a real backend in production",
                            setting=f"CACHES['{cache_name}'].BACKEND",
                        )
                elif key.upper() == "LOCATION" and value:
                    if _redis_has_no_auth(value):
                        self._add(
                            cache_config.lineno,
                            "redis_cache_no_password",
                            "high",
                            "Redis cache URL has no password — require authentication",
                            setting=f"CACHES['{cache_name}'].LOCATION",
                        )
                    elif _MEMCACHED_PLAIN_RE.search(value) and "@" not in value:
                        self._add(
                            cache_config.lineno,
                            "memcached_no_auth",
                            "medium",
                            "Memcached without SASL authentication — restrict network access or enable auth",
                            setting=f"CACHES['{cache_name}'].LOCATION",
                        )


class InsecureCacheSettingsAnalyzer:
    """Detect insecure cache configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureCacheSettingsFinding] = []
        self._stats: InsecureCacheSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureCacheSettingsFinding]:
        findings: list[InsecureCacheSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureCacheSettingsVisitor(rel, filename)
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
            if _LOCMEM_BACKEND_RE.search(line):
                findings.append(
                    InsecureCacheSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="locmem_cache_in_production",
                        severity="high",
                        message="LocMemCache is not shared across processes — use Redis or Memcached",
                        setting="BACKEND",
                    )
                )
            if _DUMMY_BACKEND_RE.search(line):
                findings.append(
                    InsecureCacheSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="dummy_cache_in_production",
                        severity="medium",
                        message="DummyCache disables caching entirely — use a real backend in production",
                        setting="BACKEND",
                    )
                )
            if _REDIS_NO_AUTH_RE.search(line):
                findings.append(
                    InsecureCacheSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="redis_cache_no_password",
                        severity="high",
                        message="Redis cache URL has no password — require authentication",
                        setting="LOCATION",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureCacheSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureCacheSettingsFinding] = []
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
        self._stats = InsecureCacheSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureCacheSettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure cache settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure cache settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure cache configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
