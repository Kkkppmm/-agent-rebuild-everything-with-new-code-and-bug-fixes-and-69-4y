"""InsecureCorsSettingsAnalyzer — detect insecure CORS configuration in settings."""

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
        "cors.py",
    }
)
_ALLOW_ALL_RE = re.compile(
    r"(CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True",
    re.IGNORECASE,
)
_WILDCARD_ORIGINS_RE = re.compile(
    r"(CORS_ALLOWED_ORIGINS|CORS_ORIGINS_WHITELIST|allow_origins)\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
_CREDENTIALS_RE = re.compile(
    r"(CORS_ALLOW_CREDENTIALS|allow_credentials)\s*=\s*True",
    re.IGNORECASE,
)
_WILDCARD_STRING_RE = re.compile(
    r"(CORS_ALLOWED_ORIGINS|allow_origins)\s*=\s*['\"]\*['\"]",
    re.IGNORECASE,
)


@dataclass
class InsecureCorsSettingsFinding:
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
class InsecureCorsSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


def _list_contains_wildcard(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List):
        return any(
            isinstance(elt, ast.Constant) and elt.value == "*"
            for elt in node.elts
        )
    if isinstance(node, ast.Tuple):
        return any(
            isinstance(elt, ast.Constant) and elt.value == "*"
            for elt in node.elts
        )
    return False


_CORS_ALLOW_ALL_NAMES = frozenset(
    {
        "CORS_ALLOW_ALL_ORIGINS",
        "CORS_ORIGIN_ALLOW_ALL",
    }
)
_CORS_ORIGIN_LIST_NAMES = frozenset(
    {
        "CORS_ALLOWED_ORIGINS",
        "CORS_ORIGINS_WHITELIST",
        "allow_origins",
    }
)
_CORS_CREDENTIALS_NAMES = frozenset(
    {
        "CORS_ALLOW_CREDENTIALS",
        "allow_credentials",
    }
)


class _InsecureCorsSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureCorsSettingsFinding] = []
        self._allow_all = False
        self._wildcard_origins = False
        self._allow_credentials = False

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureCorsSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if name in _CORS_ALLOW_ALL_NAMES and _bool_value(node.value) is True:
                self._allow_all = True
                self._add(
                    node.lineno,
                    "cors_allow_all_origins",
                    "high",
                    "CORS allows all origins — restrict to trusted domains",
                    setting=name,
                )
            elif name in _CORS_ORIGIN_LIST_NAMES and _list_contains_wildcard(node.value):
                self._wildcard_origins = True
                self._add(
                    node.lineno,
                    "cors_wildcard_origin",
                    "high",
                    "CORS origin list includes wildcard (*) — specify trusted domains",
                    setting=name,
                )
            elif name in _CORS_ORIGIN_LIST_NAMES and isinstance(node.value, ast.Constant):
                if node.value.value == "*":
                    self._wildcard_origins = True
                    self._add(
                        node.lineno,
                        "cors_wildcard_origin",
                        "high",
                        "CORS allows all origins via wildcard string — restrict to trusted domains",
                        setting=name,
                    )
            elif name in _CORS_CREDENTIALS_NAMES and _bool_value(node.value) is True:
                self._allow_credentials = True
                severity = "critical" if (self._allow_all or self._wildcard_origins) else "medium"
                message = (
                    "CORS allows credentials with permissive origins — "
                    "browsers may expose authenticated responses to untrusted sites"
                    if severity == "critical"
                    else "CORS allows credentials — ensure origins are explicitly trusted"
                )
                self._add(
                    node.lineno,
                    "cors_allow_credentials",
                    severity,
                    message,
                    setting=name,
                )
        self.generic_visit(node)


class InsecureCorsSettingsAnalyzer:
    """Detect insecure CORS configuration in Django, FastAPI, and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureCorsSettingsFinding] = []
        self._stats: InsecureCorsSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureCorsSettingsFinding]:
        findings: list[InsecureCorsSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureCorsSettingsVisitor(rel, filename)
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
            if _ALLOW_ALL_RE.search(line):
                findings.append(
                    InsecureCorsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="cors_allow_all_origins",
                        severity="high",
                        message="CORS allows all origins — restrict to trusted domains",
                        setting="CORS_ALLOW_ALL_ORIGINS",
                    )
                )
            if _WILDCARD_ORIGINS_RE.search(line) or _WILDCARD_STRING_RE.search(line):
                findings.append(
                    InsecureCorsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="cors_wildcard_origin",
                        severity="high",
                        message="CORS origin list includes wildcard (*) — specify trusted domains",
                        setting="CORS_ALLOWED_ORIGINS",
                    )
                )
            if _CREDENTIALS_RE.search(line):
                has_wildcard = bool(
                    _ALLOW_ALL_RE.search(source)
                    or _WILDCARD_ORIGINS_RE.search(source)
                    or _WILDCARD_STRING_RE.search(source)
                )
                findings.append(
                    InsecureCorsSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="cors_allow_credentials",
                        severity="critical" if has_wildcard else "medium",
                        message=(
                            "CORS allows credentials with permissive origins — "
                            "browsers may expose authenticated responses to untrusted sites"
                            if has_wildcard
                            else "CORS allows credentials — ensure origins are explicitly trusted"
                        ),
                        setting="CORS_ALLOW_CREDENTIALS",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureCorsSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureCorsSettingsFinding] = []
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
        self._stats = InsecureCorsSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureCorsSettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        critical = sum(1 for f in self._findings if f.severity == "critical")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 35.0 + high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure CORS settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure CORS settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure CORS configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
