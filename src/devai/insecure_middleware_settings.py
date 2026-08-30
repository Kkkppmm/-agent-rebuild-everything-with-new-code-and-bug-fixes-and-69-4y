"""InsecureMiddlewareSettingsAnalyzer — detect insecure Django middleware configuration."""

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
        "middleware.py",
    }
)
_REQUIRED_MIDDLEWARE = (
    ("SecurityMiddleware", "missing_security_middleware", "high"),
    ("CsrfViewMiddleware", "missing_csrf_middleware", "high"),
    ("XFrameOptionsMiddleware", "missing_clickjacking_middleware", "medium"),
)
_DEBUG_TOOLBAR_RE = re.compile(
    r"debug_toolbar\.middleware\.DebugToolbarMiddleware|DebugToolbarMiddleware",
    re.IGNORECASE,
)
_MIDDLEWARE_ASSIGN_RE = re.compile(
    r"MIDDLEWARE\s*=\s*\[",
    re.IGNORECASE,
)


@dataclass
class InsecureMiddlewareSettingsFinding:
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
class InsecureMiddlewareSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _list_string_values(node: ast.AST) -> list[str]:
    if not isinstance(node, ast.List):
        return []
    values: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            values.append(elt.value)
    return values


def _middleware_contains(middleware: list[str], needle: str) -> bool:
    needle_lower = needle.lower()
    return any(needle_lower in entry.lower() for entry in middleware)


class _InsecureMiddlewareSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureMiddlewareSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureMiddlewareSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def _check_middleware_list(self, lineno: int, middleware: list[str]) -> None:
        if not middleware:
            self._add(
                lineno,
                "empty_middleware",
                "medium",
                "MIDDLEWARE is empty — security middleware will not run",
                setting="MIDDLEWARE",
            )
            return

        for needle, pattern, severity in _REQUIRED_MIDDLEWARE:
            if not _middleware_contains(middleware, needle):
                self._add(
                    lineno,
                    pattern,
                    severity,
                    f"MIDDLEWARE missing {needle} — required for production security",
                    setting="MIDDLEWARE",
                )

        for entry in middleware:
            if _DEBUG_TOOLBAR_RE.search(entry):
                self._add(
                    lineno,
                    "debug_toolbar_in_production",
                    "high",
                    "DebugToolbarMiddleware enabled in production settings — exposes internals",
                    setting="MIDDLEWARE",
                )
                break

        cors_idx = next(
            (
                idx
                for idx, entry in enumerate(middleware)
                if "corsmiddleware" in entry.lower().replace("_", "")
            ),
            None,
        )
        security_idx = next(
            (
                idx
                for idx, entry in enumerate(middleware)
                if "securitymiddleware" in entry.lower().replace("_", "")
            ),
            None,
        )
        if cors_idx is not None and security_idx is not None and cors_idx < security_idx:
            self._add(
                lineno,
                "cors_before_security_middleware",
                "medium",
                "CorsMiddleware appears before SecurityMiddleware — reorder for correct CORS headers",
                setting="MIDDLEWARE",
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for target in node.targets:
            if not isinstance(target, ast.Name) or target.id != "MIDDLEWARE":
                continue
            middleware = _list_string_values(node.value)
            if middleware or isinstance(node.value, ast.List):
                self._check_middleware_list(node.lineno, middleware)
        self.generic_visit(node)


class InsecureMiddlewareSettingsAnalyzer:
    """Detect insecure Django middleware configuration in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureMiddlewareSettingsFinding] = []
        self._stats: InsecureMiddlewareSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureMiddlewareSettingsFinding]:
        findings: list[InsecureMiddlewareSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureMiddlewareSettingsVisitor(rel, filename)
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
            if _DEBUG_TOOLBAR_RE.search(line) and "MIDDLEWARE" in line:
                findings.append(
                    InsecureMiddlewareSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="debug_toolbar_in_production",
                        severity="high",
                        message="DebugToolbarMiddleware enabled in production settings — exposes internals",
                        setting="MIDDLEWARE",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureMiddlewareSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureMiddlewareSettingsFinding] = []
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
        self._stats = InsecureMiddlewareSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureMiddlewareSettingsStats:
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
            f"Insecure middleware settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure middleware settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure middleware configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
