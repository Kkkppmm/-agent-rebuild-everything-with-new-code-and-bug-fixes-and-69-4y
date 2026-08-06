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
_LOG_LEVEL_DEBUG_RE = re.compile(
    r"LOG_LEVEL\s*=\s*['\"]DEBUG['\"]",
    re.IGNORECASE,
)
_SENSITIVE_FORMAT_RE = re.compile(
    r"(password|token|secret|api[_-]?key|authorization|credential)",
    re.IGNORECASE,
)
_CONSOLE_HANDLER_RE = re.compile(
    r"(logging\.StreamHandler|StreamHandler|console)",
    re.IGNORECASE,
)
_FILE_HANDLER_RE = re.compile(
    r"(?<![a-zA-Z])(?:logging\.)?FileHandler(?![a-zA-Z])",
    re.IGNORECASE,
)
_BASIC_CONFIG_DEBUG_RE = re.compile(
    r"basicConfig\s*\([^)]*level\s*=\s*(logging\.)?DEBUG",
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
    return None


def _is_debug_level(value: str) -> bool:
    return value.upper() == "DEBUG"


class _InsecureLoggingSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureLoggingSettingsFinding] = []
        self._in_logging = False

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
            if name == "DEBUG":
                value = _bool_value(node.value)
                if value is True:
                    self._add(
                        node.lineno,
                        "debug_enabled_in_production",
                        "high",
                        "DEBUG=True exposes stack traces and sensitive data — disable in production",
                        setting="DEBUG",
                    )
            elif name == "LOG_LEVEL":
                value = _dict_string_value(node.value)
                if value and _is_debug_level(value):
                    self._add(
                        node.lineno,
                        "log_level_debug_in_production",
                        "high",
                        "LOG_LEVEL=DEBUG logs sensitive details — use INFO or WARNING in production",
                        setting="LOG_LEVEL",
                    )
            elif name == "LOGGING" and isinstance(node.value, ast.Dict):
                self._scan_logging_dict(node.value)
        self.generic_visit(node)

    def _scan_logging_dict(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key is None:
                continue
            if key == "formatters" and isinstance(value_node, ast.Dict):
                self._scan_formatters(value_node)
            elif key == "handlers" and isinstance(value_node, ast.Dict):
                self._scan_handlers(value_node)
            elif key == "root" and isinstance(value_node, ast.Dict):
                self._scan_root_logger(value_node)

    def _scan_formatters(self, node: ast.Dict) -> None:
        for _, formatter_config in zip(node.keys, node.values):
            if not isinstance(formatter_config, ast.Dict):
                continue
            for fmt_key, fmt_val in zip(formatter_config.keys, formatter_config.values):
                fmt_key_name = _dict_string_value(fmt_key) if fmt_key else None
                if fmt_key_name not in ("format", "fmt"):
                    continue
                fmt_str = _dict_string_value(fmt_val)
                if fmt_str and _SENSITIVE_FORMAT_RE.search(fmt_str):
                    self._add(
                        formatter_config.lineno,
                        "sensitive_log_format",
                        "medium",
                        "Log format may include sensitive fields — avoid logging passwords or tokens",
                        setting="LOGGING['formatters']",
                    )

    def _scan_handlers(self, node: ast.Dict) -> None:
        for handler_key, handler_config in zip(node.keys, node.values):
            if not isinstance(handler_config, ast.Dict):
                continue
            handler_name = _dict_string_value(handler_key) if handler_key else "handler"
            backend = ""
            level = ""
            for hkey, hval in zip(handler_config.keys, handler_config.values):
                hkey_name = _dict_string_value(hkey) if hkey else None
                if hkey_name == "class":
                    backend = _dict_string_value(hval) or ""
                elif hkey_name == "level":
                    level = _dict_string_value(hval) or ""

            if "StreamHandler" in backend and self.filename in _PROD_FILENAMES:
                self._add(
                    handler_config.lineno,
                    "console_handler_in_production",
                    "medium",
                    "Console logging writes to stdout — use file or centralized logging in production",
                    setting=f"LOGGING['handlers']['{handler_name}']",
                )
            if "FileHandler" in backend and "Rotating" not in backend:
                self._add(
                    handler_config.lineno,
                    "file_logging_no_rotation",
                    "low",
                    "FileHandler without rotation can fill disk — use RotatingFileHandler or TimedRotatingFileHandler",
                    setting=f"LOGGING['handlers']['{handler_name}']",
                )
            if level and _is_debug_level(level):
                self._add(
                    handler_config.lineno,
                    "handler_debug_level",
                    "medium",
                    "Handler configured at DEBUG level — reduce verbosity in production",
                    setting=f"LOGGING['handlers']['{handler_name}'].level",
                )

    def _scan_root_logger(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key == "level":
                level = _dict_string_value(value_node)
                if level and _is_debug_level(level):
                    self._add(
                        node.lineno,
                        "root_logger_debug",
                        "high",
                        "Root logger at DEBUG level — use INFO or WARNING in production",
                        setting="LOGGING['root'].level",
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
                        message="DEBUG=True exposes stack traces and sensitive data — disable in production",
                        setting="DEBUG",
                    )
                )
            if _LOG_LEVEL_DEBUG_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="log_level_debug_in_production",
                        severity="high",
                        message="LOG_LEVEL=DEBUG logs sensitive details — use INFO or WARNING in production",
                        setting="LOG_LEVEL",
                    )
                )
            if _BASIC_CONFIG_DEBUG_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="basic_config_debug",
                        severity="high",
                        message="logging.basicConfig(level=DEBUG) is too verbose for production",
                        setting="logging.basicConfig",
                    )
                )
            if _SENSITIVE_FORMAT_RE.search(line) and (
                "format" in line.lower() or "fmt" in line.lower()
            ):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="sensitive_log_format",
                        severity="medium",
                        message="Log format may include sensitive fields — avoid logging passwords or tokens",
                        setting="LOGGING format",
                    )
                )
            if _CONSOLE_HANDLER_RE.search(line) and "handler" in line.lower():
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="console_handler_in_production",
                        severity="medium",
                        message="Console logging writes to stdout — use file or centralized logging in production",
                        setting="LOGGING handler",
                    )
                )
            if _FILE_HANDLER_RE.search(line) and "Rotating" not in line:
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="file_logging_no_rotation",
                        severity="low",
                        message="FileHandler without rotation can fill disk — use RotatingFileHandler",
                        setting="LOGGING handler",
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
