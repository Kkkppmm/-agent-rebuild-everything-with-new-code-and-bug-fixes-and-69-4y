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
_DEBUG_TRUE_RE = re.compile(r"\bDEBUG\s*=\s*True\b")
_CONSOLE_HANDLER_RE = re.compile(
    r"(logging\.StreamHandler|StreamHandler|"
    r"logging\.handlers\.StreamHandler|"
    r"['\"]console['\"]\s*:\s*\{)",
    re.IGNORECASE,
)
_DEBUG_LEVEL_RE = re.compile(
    r"['\"]level['\"]\s*:\s*['\"]DEBUG['\"]|"
    r"level\s*=\s*logging\.DEBUG|"
    r"['\"]level['\"]\s*:\s*logging\.DEBUG",
    re.IGNORECASE,
)
_SENSITIVE_FORMAT_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "session_key",
    "cookie",
    "bearer",
)
_SENSITIVE_FORMAT_RE = re.compile(
    r"['\"].*(?:password|passwd|secret|token|api_key|apikey|authorization|"
    r"credential|private_key|session_key|cookie|bearer).*['\"]",
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


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _contains_sensitive_format(value: str) -> bool:
    lower = value.lower()
    return any(fragment in lower for fragment in _SENSITIVE_FORMAT_FRAGMENTS)


class _InsecureLoggingSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureLoggingSettingsFinding] = []
        self._in_logging_dict = False
        self._logging_depth = 0

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
        if self.filename in _PROD_FILENAMES:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG":
                    if _bool_value(node.value) is True:
                        self._add(
                            node.lineno,
                            "debug_in_production",
                            "high",
                            "DEBUG = True in production settings exposes sensitive data and stack traces",
                            setting="DEBUG",
                        )
                if isinstance(target, ast.Name) and target.id == "LOGGING":
                    self._scan_logging_value(node.value, node.lineno)
        self.generic_visit(node)

    def _scan_logging_value(self, node: ast.AST, lineno: int) -> None:
        if not isinstance(node, ast.Dict):
            return
        for key, value in zip(node.keys, node.values, strict=False):
            key_str = _dict_string_value(key) if key is not None else None
            if key_str == "handlers" and isinstance(value, ast.Dict):
                self._scan_handlers(value, lineno)
            elif key_str == "formatters" and isinstance(value, ast.Dict):
                self._scan_formatters(value, lineno)
            elif key_str == "loggers" and isinstance(value, ast.Dict):
                self._scan_loggers(value, lineno)

    def _scan_handlers(self, node: ast.Dict, lineno: int) -> None:
        for handler_key, handler_val in zip(node.keys, node.values, strict=False):
            handler_name = _dict_string_value(handler_key) if handler_key is not None else ""
            if not isinstance(handler_val, ast.Dict):
                continue
            handler_class: str | None = None
            for hk, hv in zip(handler_val.keys, handler_val.values, strict=False):
                hk_str = _dict_string_value(hk) if hk is not None else None
                if hk_str == "class":
                    handler_class = _dict_string_value(hv)
            if handler_class and (
                "StreamHandler" in handler_class or handler_name.lower() == "console"
            ):
                self._add(
                    lineno,
                    "console_log_handler",
                    "medium",
                    "Console/stream log handler writes logs to stdout — use file or centralized logging in production",
                    setting="LOGGING.handlers",
                )

    def _scan_formatters(self, node: ast.Dict, lineno: int) -> None:
        for _, formatter_val in zip(node.keys, node.values, strict=False):
            if not isinstance(formatter_val, ast.Dict):
                continue
            for fk, fv in zip(formatter_val.keys, formatter_val.values, strict=False):
                fk_str = _dict_string_value(fk) if fk is not None else None
                if fk_str in {"format", "datefmt"}:
                    fmt = _dict_string_value(fv)
                    if fmt and _contains_sensitive_format(fmt):
                        self._add(
                            lineno,
                            "sensitive_log_format",
                            "high",
                            "Log format string may include sensitive fields — avoid logging passwords, tokens, or credentials",
                            setting="LOGGING.formatters",
                        )

    def _scan_loggers(self, node: ast.Dict, lineno: int) -> None:
        for _, logger_val in zip(node.keys, node.values, strict=False):
            if not isinstance(logger_val, ast.Dict):
                continue
            for lk, lv in zip(logger_val.keys, logger_val.values, strict=False):
                lk_str = _dict_string_value(lk) if lk is not None else None
                if lk_str == "level":
                    level = _dict_string_value(lv)
                    if level and level.upper() == "DEBUG":
                        self._add(
                            lineno,
                            "debug_log_level",
                            "medium",
                            "Logger level set to DEBUG in production — use INFO or WARNING to reduce sensitive output",
                            setting="LOGGING.loggers",
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
                        pattern="debug_in_production",
                        severity="high",
                        message="DEBUG = True in production settings exposes sensitive data and stack traces",
                        setting="DEBUG",
                    )
                )
            if _CONSOLE_HANDLER_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="console_log_handler",
                        severity="medium",
                        message="Console/stream log handler writes logs to stdout — use file or centralized logging in production",
                        setting="LOGGING.handlers",
                    )
                )
            if _DEBUG_LEVEL_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="debug_log_level",
                        severity="medium",
                        message="Logger level set to DEBUG in production — use INFO or WARNING to reduce sensitive output",
                        setting="LOGGING.loggers",
                    )
                )
            if _SENSITIVE_FORMAT_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="sensitive_log_format",
                        severity="high",
                        message="Log format string may include sensitive fields — avoid logging passwords, tokens, or credentials",
                        setting="LOGGING.formatters",
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
