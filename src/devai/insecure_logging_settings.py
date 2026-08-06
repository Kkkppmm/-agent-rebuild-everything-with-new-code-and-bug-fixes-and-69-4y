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
_DEBUG_LEVEL_RE = re.compile(
    r"(LOG_LEVEL|DJANGO_LOG_LEVEL|LOGGING_LEVEL)\s*=\s*['\"]DEBUG['\"]",
    re.IGNORECASE,
)
_LOGGING_DEBUG_RE = re.compile(
    r"logging\.DEBUG\b|['\"]level['\"]\s*:\s*['\"]DEBUG['\"]|'level'\s*:\s*logging\.DEBUG",
    re.IGNORECASE,
)
_CONSOLE_HANDLER_RE = re.compile(
    r"(logging\.StreamHandler|StreamHandler)\s*\(",
    re.IGNORECASE,
)
_CONSOLE_HANDLER_CLASS_RE = re.compile(
    r"['\"]class['\"]\s*:\s*['\"]logging\.StreamHandler['\"]",
    re.IGNORECASE,
)
_SENSITIVE_FORMAT_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|bearer|credential)",
    re.IGNORECASE,
)
_FORMAT_STRING_RE = re.compile(
    r"(format|fmt)\s*[=:]\s*['\"]([^'\"]+)['\"]",
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


def _is_debug_level(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value.upper() == "DEBUG"
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
        return value.value.id == "logging" and value.attr == "DEBUG"
    return False


def _handler_is_console(value: ast.AST) -> bool:
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Attribute) and func.attr == "StreamHandler":
            return True
        if isinstance(func, ast.Name) and func.id == "StreamHandler":
            return True
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return "StreamHandler" in value.value
    return False


def _format_contains_sensitive(value: str) -> bool:
    return bool(_SENSITIVE_FORMAT_RE.search(value))


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
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {
                "LOG_LEVEL",
                "DJANGO_LOG_LEVEL",
                "LOGGING_LEVEL",
            }:
                if _is_debug_level(node.value) and self.filename in _PROD_FILENAMES:
                    self._add(
                        node.lineno,
                        "debug_logging_in_production",
                        "high",
                        "DEBUG log level in production exposes sensitive data — use INFO or WARNING",
                        setting=target.id,
                    )
            if isinstance(target, ast.Name) and target.id == "LOGGING":
                if isinstance(node.value, ast.Dict):
                    self._scan_logging_dict(node.value)
        self.generic_visit(node)

    def _scan_logging_dict(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key is None:
                continue
            key_lower = key.lower()
            if key_lower == "handlers" and isinstance(value_node, ast.Dict):
                self._scan_handlers(value_node)
            elif key_lower == "loggers" and isinstance(value_node, ast.Dict):
                self._scan_loggers(value_node)
            elif key_lower == "root" and isinstance(value_node, ast.Dict):
                self._scan_logger_config(value_node, "root")

    def _scan_handlers(self, node: ast.Dict) -> None:
        for handler_key, handler_config in zip(node.keys, node.values):
            if not isinstance(handler_config, ast.Dict):
                continue
            handler_name = _dict_string_value(handler_key) if handler_key else "handler"
            handler_name = handler_name or "handler"
            for key_node, value_node in zip(handler_config.keys, handler_config.values):
                key = _dict_string_value(key_node) if key_node else None
                if key is None:
                    continue
                if key.lower() == "class":
                    value = _dict_string_value(value_node)
                    if value and "StreamHandler" in value and self.filename in _PROD_FILENAMES:
                        self._add(
                            handler_config.lineno,
                            "console_handler_in_production",
                            "medium",
                            "StreamHandler writes logs to stdout — use file or centralized logging in production",
                            setting=f"LOGGING['handlers']['{handler_name}'].class",
                        )
                elif key.lower() in {"formatter", "format"}:
                    value = _dict_string_value(value_node)
                    if value and _format_contains_sensitive(value):
                        self._add(
                            handler_config.lineno,
                            "sensitive_log_format",
                            "high",
                            "Log format includes sensitive field names — avoid logging secrets and credentials",
                            setting=f"LOGGING['handlers']['{handler_name}'].{key}",
                        )

    def _scan_loggers(self, node: ast.Dict) -> None:
        for logger_key, logger_config in zip(node.keys, node.values):
            if isinstance(logger_config, ast.Dict):
                name = _dict_string_value(logger_key) if logger_key else "logger"
                self._scan_logger_config(logger_config, name or "logger")

    def _scan_logger_config(self, node: ast.Dict, logger_name: str) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key is None:
                continue
            if key.lower() == "level" and _is_debug_level(value_node):
                if self.filename in _PROD_FILENAMES:
                    self._add(
                        node.lineno,
                        "debug_logging_in_production",
                        "high",
                        "DEBUG log level in production exposes sensitive data — use INFO or WARNING",
                        setting=f"LOGGING loggers['{logger_name}'].level",
                    )
            if key.lower() == "handlers" and isinstance(value_node, ast.List):
                for elt in value_node.elts:
                    value = _dict_string_value(elt)
                    if value and "console" in value.lower() and self.filename in _PROD_FILENAMES:
                        self._add(
                            node.lineno,
                            "console_handler_in_production",
                            "medium",
                            "Console handler referenced in production logging config",
                            setting=f"LOGGING loggers['{logger_name}'].handlers",
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
            if _DEBUG_LEVEL_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="debug_logging_in_production",
                        severity="high",
                        message="DEBUG log level in production exposes sensitive data — use INFO or WARNING",
                        setting="LOG_LEVEL",
                    )
                )
            if _LOGGING_DEBUG_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="debug_logging_in_production",
                        severity="high",
                        message="DEBUG log level in production exposes sensitive data — use INFO or WARNING",
                        setting="LOGGING",
                    )
                )
            if _CONSOLE_HANDLER_RE.search(line) or _CONSOLE_HANDLER_CLASS_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="console_handler_in_production",
                        severity="medium",
                        message="StreamHandler writes logs to stdout — use file or centralized logging in production",
                        setting="handlers",
                    )
                )
            format_match = _FORMAT_STRING_RE.search(line)
            if format_match and _format_contains_sensitive(format_match.group(2)):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="sensitive_log_format",
                        severity="high",
                        message="Log format includes sensitive field names — avoid logging secrets and credentials",
                        setting="format",
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
