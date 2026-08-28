"""InsecureLoggingSettingsAnalyzer — detect insecure logging configuration."""

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
        "logging.py",
    }
)
_DEBUG_TRUE_RE = re.compile(r"DEBUG\s*=\s*True\b")
_CONSOLE_HANDLER_RE = re.compile(
    r"(logging\.StreamHandler|StreamHandler|console\.Handler)",
    re.IGNORECASE,
)
_SENSITIVE_FORMAT_RE = re.compile(
    r"(password|secret|token|api_key|credential|authorization|session_key)",
    re.IGNORECASE,
)
_VERBOSE_LEVEL_RE = re.compile(
    r"['\"]level['\"]\s*:\s*['\"]DEBUG['\"]|LOGGING_LEVEL\s*=\s*['\"]DEBUG['\"]",
    re.IGNORECASE,
)


@dataclass
class InsecureLoggingSettingsFinding:
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
class InsecureLoggingSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


class _InsecureLoggingSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureLoggingSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureLoggingSettingsFinding(
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
            if name == "DEBUG" and _bool_value(node.value) is True:
                self._add(
                    node.lineno,
                    "debug_enabled_in_production",
                    "high",
                    "DEBUG=True exposes sensitive error details — disable in production",
                    setting="DEBUG",
                )
            elif name == "LOGGING" and isinstance(node.value, ast.Dict):
                self._scan_logging_dict(node.value)
            elif name == "LOGGING_LEVEL":
                value = _dict_string_value(node.value)
                if value and value.upper() == "DEBUG":
                    self._add(
                        node.lineno,
                        "verbose_logging_in_production",
                        "medium",
                        "DEBUG log level in production may leak sensitive data",
                        setting="LOGGING_LEVEL",
                    )
        self.generic_visit(node)

    def _scan_logging_dict(self, node: ast.Dict) -> None:
        handlers = None
        formatters = None
        for key, value in zip(node.keys, node.values):
            key_name = _dict_string_value(key) if key else None
            if key_name == "handlers" and isinstance(value, ast.Dict):
                handlers = value
            if key_name == "formatters" and isinstance(value, ast.Dict):
                formatters = value

        if handlers:
            for handler_key, handler_config in zip(handlers.keys, handlers.values):
                if not isinstance(handler_config, ast.Dict):
                    continue
                handler_name = _dict_string_value(handler_key) if handler_key else "handler"
                for hk, hv in zip(handler_config.keys, handler_config.values):
                    hk_name = _dict_string_value(hk) if hk else None
                    if hk_name == "class":
                        class_value = _dict_string_value(hv)
                        if class_value and _CONSOLE_HANDLER_RE.search(class_value):
                            self._add(
                                handler_config.lineno,
                                "console_handler_in_production",
                                "medium",
                                f"Console/stream logging handler '{handler_name}' writes to stdout in production",
                                setting="LOGGING.handlers",
                            )

        if formatters:
            for fmt_key, fmt_config in zip(formatters.keys, formatters.values):
                if not isinstance(fmt_config, ast.Dict):
                    continue
                fmt_name = _dict_string_value(fmt_key) if fmt_key else "formatter"
                for fk, fv in zip(fmt_config.keys, fmt_config.values):
                    fk_name = _dict_string_value(fk) if fk else None
                    if fk_name == "format":
                        fmt_value = _dict_string_value(fv)
                        if fmt_value and _SENSITIVE_FORMAT_RE.search(fmt_value):
                            self._add(
                                fmt_config.lineno,
                                "sensitive_log_format",
                                "high",
                                f"Log formatter '{fmt_name}' may include sensitive fields in output",
                                setting="LOGGING.formatters",
                            )


class InsecureLoggingSettingsAnalyzer:
    """Detect insecure logging configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureLoggingSettingsFinding] = []
        self._stats: InsecureLoggingSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureLoggingSettingsFinding]:
        findings: list[InsecureLoggingSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureLoggingSettingsVisitor(rel, filename)
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
            if _DEBUG_TRUE_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="debug_enabled_in_production",
                        severity="high",
                        message="DEBUG=True exposes sensitive error details — disable in production",
                        setting="DEBUG",
                    )
                )
            if _CONSOLE_HANDLER_RE.search(line) and "LOGGING" in source:
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="console_handler_in_production",
                        severity="medium",
                        message="Console/stream logging handler writes to stdout in production",
                        setting="LOGGING.handlers",
                    )
                )
            if _VERBOSE_LEVEL_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="verbose_logging_in_production",
                        severity="medium",
                        message="DEBUG log level in production may leak sensitive data",
                        setting="LOGGING",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureLoggingSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureLoggingSettingsFinding] = []
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
        self._stats = InsecureLoggingSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureLoggingSettingsStats:
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
            f"Insecure logging settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure logging settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure logging configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
