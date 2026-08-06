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
_DEBUG_TRUE_RE = re.compile(r"DEBUG\s*=\s*True\b", re.IGNORECASE)
_CONSOLE_HANDLER_RE = re.compile(
    r"logging\.StreamHandler|logging\.handlers\.StreamHandler|"
    r"['\"]logging\.StreamHandler['\"]|['\"]logging\.handlers\.StreamHandler['\"]",
    re.IGNORECASE,
)
_SENSITIVE_FORMAT_RE = re.compile(
    r"(password|secret|token|api_key|authorization|credential|ssn|credit_card)",
    re.IGNORECASE,
)
_DEBUG_LEVEL_RE = re.compile(
    r"['\"]DEBUG['\"]|logging\.DEBUG",
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
            if isinstance(target, ast.Name) and target.id == "DEBUG":
                if _bool_value(node.value) is True:
                    self._add(
                        node.lineno,
                        "debug_enabled_in_production",
                        "high",
                        "DEBUG=True exposes stack traces and sensitive data — disable in production",
                        setting="DEBUG",
                    )
            elif isinstance(target, ast.Name) and target.id == "LOGGING":
                if isinstance(node.value, ast.Dict):
                    self._scan_logging_dict(node.value)
        self.generic_visit(node)

    def _scan_logging_dict(self, node: ast.Dict) -> None:
        handlers_key = None
        handlers_node = None
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key == "handlers":
                handlers_node = value_node
            elif key == "formatters":
                self._scan_formatters(value_node)

        if handlers_node and isinstance(handlers_node, ast.Dict):
            for handler_key, handler_config in zip(handlers_node.keys, handlers_node.values):
                if not isinstance(handler_config, ast.Dict):
                    continue
                handler_name = _dict_string_value(handler_key) if handler_key else "handler"
                for cfg_key, cfg_val in zip(handler_config.keys, handler_config.values):
                    cfg_key_str = _dict_string_value(cfg_key) if cfg_key else None
                    if cfg_key_str == "class":
                        cls_val = _dict_string_value(cfg_val)
                        if cls_val and "StreamHandler" in cls_val:
                            self._add(
                                handler_config.lineno,
                                "console_handler_in_production",
                                "medium",
                                "Console logging handler writes to stdout — use file or remote logging",
                                setting=f"LOGGING['handlers']['{handler_name}']",
                            )
                    elif cfg_key_str == "level":
                        level_val = _dict_string_value(cfg_val)
                        if level_val and level_val.upper() == "DEBUG":
                            self._add(
                                handler_config.lineno,
                                "debug_log_level_in_production",
                                "high",
                                "DEBUG log level in production may leak sensitive information",
                                setting=f"LOGGING['handlers']['{handler_name}'].level",
                            )

    def _scan_formatters(self, node: ast.AST) -> None:
        if not isinstance(node, ast.Dict):
            return
        for fmt_key, fmt_config in zip(node.keys, node.values):
            if not isinstance(fmt_config, ast.Dict):
                continue
            for cfg_key, cfg_val in zip(fmt_config.keys, fmt_config.values):
                cfg_key_str = _dict_string_value(cfg_key) if cfg_key else None
                if cfg_key_str == "format":
                    fmt_val = _dict_string_value(cfg_val)
                    if fmt_val and _SENSITIVE_FORMAT_RE.search(fmt_val):
                        self._add(
                            fmt_config.lineno,
                            "sensitive_log_format",
                            "medium",
                            "Log format may include sensitive fields — avoid logging secrets",
                            setting="LOGGING['formatters']",
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
            if _CONSOLE_HANDLER_RE.search(line):
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="console_handler_in_production",
                        severity="medium",
                        message="Console logging handler writes to stdout — use file or remote logging",
                        setting="LOGGING",
                    )
                )
            if _SENSITIVE_FORMAT_RE.search(line) and "format" in line.lower():
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="sensitive_log_format",
                        severity="medium",
                        message="Log format may include sensitive fields — avoid logging secrets",
                        setting="LOGGING",
                    )
                )
            if _DEBUG_LEVEL_RE.search(line) and "level" in line.lower():
                findings.append(
                    InsecureLoggingSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="debug_log_level_in_production",
                        severity="high",
                        message="DEBUG log level in production may leak sensitive information",
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
