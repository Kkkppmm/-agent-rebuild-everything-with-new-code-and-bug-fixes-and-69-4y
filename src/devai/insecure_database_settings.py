"""InsecureDatabaseSettingsAnalyzer — detect insecure database configuration."""

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
        "database.py",
    }
)
_DEFAULT_CREDENTIALS = frozenset(
    {
        ("postgres", "postgres"),
        ("root", "root"),
        ("root", ""),
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "password"),
        ("test", "test"),
        ("sa", ""),
    }
)
_SQLITE_ENGINE_RE = re.compile(
    r"(django\.db\.backends\.)?sqlite3|sqlite://",
    re.IGNORECASE,
)
_EMPTY_PASSWORD_RE = re.compile(
    r"['\"]PASSWORD['\"]\s*:\s*['\"]['\"]",
    re.IGNORECASE,
)
_DEFAULT_USER_PASS_RE = re.compile(
    r"['\"]USER['\"]\s*:\s*['\"](\w+)['\"].*?['\"]PASSWORD['\"]\s*:\s*['\"](\w*)['\"]",
    re.IGNORECASE,
)


@dataclass
class InsecureDatabaseSettingsFinding:
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
class InsecureDatabaseSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_sqlite_engine(value: str) -> bool:
    return bool(_SQLITE_ENGINE_RE.search(value))


def _extract_db_credentials(node: ast.Dict) -> list[tuple[str, str, int]]:
    """Return (user, password, lineno) tuples from a DATABASES dict literal."""
    results: list[tuple[str, str, int]] = []
    user: str | None = None
    password: str | None = None
    for key, val in zip(node.keys, node.values):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            continue
        key_name = key.value.upper()
        if key_name == "ENGINE":
            engine = _dict_string_value(val)
            if engine and _is_sqlite_engine(engine):
                results.append(("__engine__", engine, node.lineno))
        elif key_name == "USER":
            user = _dict_string_value(val)
        elif key_name == "PASSWORD":
            password = _dict_string_value(val)
    if user is not None or password is not None:
        results.append((user or "", password or "", node.lineno))
    return results


class _InsecureDatabaseSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureDatabaseSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureDatabaseSettingsFinding(
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
            if isinstance(target, ast.Name) and target.id == "DATABASES":
                if isinstance(node.value, ast.Dict):
                    self._check_databases_dict(node.value)
        self.generic_visit(node)

    def _check_databases_dict(self, node: ast.Dict) -> None:
        for key, val in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if not isinstance(val, ast.Dict):
                continue
            db_name = key.value
            for user, password, lineno in _extract_db_credentials(val):
                if user == "__engine__":
                    if self.filename in _PROD_FILENAMES:
                        self._add(
                            lineno,
                            "sqlite_in_production",
                            "high",
                            "SQLite is not suitable for production — use PostgreSQL or MySQL",
                            setting=f"DATABASES['{db_name}'].ENGINE",
                        )
                elif password == "":
                    self._add(
                        lineno,
                        "empty_database_password",
                        "high",
                        "Empty database password — use a strong credential from environment variables",
                        setting=f"DATABASES['{db_name}'].PASSWORD",
                    )
                elif (user.lower(), password.lower()) in _DEFAULT_CREDENTIALS:
                    self._add(
                        lineno,
                        "default_database_credentials",
                        "high",
                        f"Default database credentials ({user}/{password or '<empty>'}) — "
                        "use unique credentials from environment variables",
                        setting=f"DATABASES['{db_name}']",
                    )


class InsecureDatabaseSettingsAnalyzer:
    """Detect insecure database configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureDatabaseSettingsFinding] = []
        self._stats: InsecureDatabaseSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureDatabaseSettingsFinding]:
        findings: list[InsecureDatabaseSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureDatabaseSettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if filename in _PROD_FILENAMES and _SQLITE_ENGINE_RE.search(line):
                if "sqlite" in line.lower():
                    findings.append(
                        InsecureDatabaseSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="sqlite_in_production",
                            severity="high",
                            message="SQLite is not suitable for production — use PostgreSQL or MySQL",
                            setting="ENGINE",
                        )
                    )
            if _EMPTY_PASSWORD_RE.search(line):
                findings.append(
                    InsecureDatabaseSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="empty_database_password",
                        severity="high",
                        message="Empty database password — use a strong credential from environment variables",
                        setting="PASSWORD",
                    )
                )
            match = _DEFAULT_USER_PASS_RE.search(line)
            if match:
                user, password = match.group(1), match.group(2)
                if (user.lower(), password.lower()) in _DEFAULT_CREDENTIALS:
                    findings.append(
                        InsecureDatabaseSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="default_database_credentials",
                            severity="high",
                            message=(
                                f"Default database credentials ({user}/{password or '<empty>'}) — "
                                "use unique credentials from environment variables"
                            ),
                            setting="DATABASES",
                        )
                    )
        return findings

    def analyze(self) -> list[InsecureDatabaseSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureDatabaseSettingsFinding] = []
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
        self._stats = InsecureDatabaseSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureDatabaseSettingsStats:
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
            f"Insecure database settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure database settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure database configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
