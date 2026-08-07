"""InsecureCelerySettingsAnalyzer — detect insecure Celery configuration."""

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
        "celery.py",
        "celeryconfig.py",
    }
)
_PICKLE_SERIALIZER_RE = re.compile(
    r"['\"]pickle['\"]|celery\.(serialization|serializers)\.pickle",
    re.IGNORECASE,
)
_TASK_ALWAYS_EAGER_RE = re.compile(
    r"(CELERY_)?TASK_ALWAYS_EAGER\s*[:=]\s*True|task_always_eager\s*=\s*True",
    re.IGNORECASE,
)
_REDIS_NO_AUTH_RE = re.compile(
    r"redis://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_AMQP_GUEST_RE = re.compile(
    r"amqp://guest:guest@|amqps?://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_BROKER_URL_RE = re.compile(
    r"(CELERY_)?BROKER_URL|broker_url|result_backend",
    re.IGNORECASE,
)


@dataclass
class InsecureCelerySettingsFinding:
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
class InsecureCelerySettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _list_string_values(node: ast.AST) -> list[str]:
    if not isinstance(node, ast.List):
        return []
    values: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            values.append(elt.value)
    return values


def _contains_pickle(values: list[str]) -> bool:
    return any(value.lower() == "pickle" for value in values)


def _is_pickle_serializer(value: str) -> bool:
    return value.lower() == "pickle"


def _redis_has_no_auth(value: str) -> bool:
    if "redis://" not in value.lower():
        return False
    return bool(_REDIS_NO_AUTH_RE.search(value))


def _amqp_is_insecure(value: str) -> bool:
    lower = value.lower()
    if "amqp://" not in lower and "amqps://" not in lower:
        return False
    if "guest:guest@" in lower:
        return True
    return bool(_AMQP_GUEST_RE.search(value))


class _InsecureCelerySettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureCelerySettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureCelerySettingsFinding(
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
            if isinstance(target, ast.Name):
                self._scan_setting(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _scan_setting(self, name: str, value_node: ast.AST, lineno: int) -> None:
        upper = name.upper()

        if upper in {"CELERY_ACCEPT_CONTENT", "ACCEPT_CONTENT"}:
            values = _list_string_values(value_node)
            if _contains_pickle(values):
                self._add(
                    lineno,
                    "pickle_accept_content",
                    "critical",
                    "Celery accepts pickle content — enables remote code execution via malicious tasks",
                    setting=name,
                )
        elif upper in {"CELERY_TASK_SERIALIZER", "TASK_SERIALIZER"}:
            value = _dict_string_value(value_node)
            if value and _is_pickle_serializer(value):
                self._add(
                    lineno,
                    "pickle_task_serializer",
                    "critical",
                    "Celery task serializer set to pickle — use json or msgpack instead",
                    setting=name,
                )
        elif upper in {"CELERY_RESULT_SERIALIZER", "RESULT_SERIALIZER"}:
            value = _dict_string_value(value_node)
            if value and _is_pickle_serializer(value):
                self._add(
                    lineno,
                    "pickle_result_serializer",
                    "high",
                    "Celery result serializer set to pickle — use json or msgpack instead",
                    setting=name,
                )
        elif upper in {"CELERY_TASK_ALWAYS_EAGER", "TASK_ALWAYS_EAGER"}:
            if isinstance(value_node, ast.Constant) and value_node.value is True:
                self._add(
                    lineno,
                    "task_always_eager",
                    "high",
                    "CELERY_TASK_ALWAYS_EAGER is True — tasks run synchronously; disable in production",
                    setting=name,
                )
        elif upper in {"CELERY_BROKER_URL", "BROKER_URL"}:
            value = _dict_string_value(value_node)
            if value:
                self._scan_broker_url(lineno, value, name)
        elif upper in {"CELERY_RESULT_BACKEND", "RESULT_BACKEND"}:
            value = _dict_string_value(value_node)
            if value:
                self._scan_result_backend(lineno, value, name)

    def _scan_broker_url(self, lineno: int, value: str, setting: str) -> None:
        if _redis_has_no_auth(value):
            self._add(
                lineno,
                "unauthenticated_redis_broker",
                "high",
                "Celery broker uses Redis without authentication — secure the connection with a password",
                setting=setting,
            )
        elif _amqp_is_insecure(value):
            self._add(
                lineno,
                "unauthenticated_amqp_broker",
                "high",
                "Celery broker uses default or unauthenticated AMQP credentials — use strong credentials",
                setting=setting,
            )

    def _scan_result_backend(self, lineno: int, value: str, setting: str) -> None:
        if _redis_has_no_auth(value):
            self._add(
                lineno,
                "unauthenticated_redis_backend",
                "medium",
                "Celery result backend uses Redis without authentication — secure the connection",
                setting=setting,
            )


class InsecureCelerySettingsAnalyzer:
    """Detect insecure Celery configuration in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureCelerySettingsFinding] = []
        self._stats: InsecureCelerySettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureCelerySettingsFinding]:
        findings: list[InsecureCelerySettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureCelerySettingsVisitor(rel, filename)
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
            if _PICKLE_SERIALIZER_RE.search(line) and (
                "CELERY" in source or "celery" in source.lower()
            ):
                findings.append(
                    InsecureCelerySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="pickle_serializer",
                        severity="critical",
                        message="Celery pickle serializer detected — use json or msgpack to prevent RCE",
                    )
                )
            if _TASK_ALWAYS_EAGER_RE.search(line):
                findings.append(
                    InsecureCelerySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="task_always_eager",
                        severity="high",
                        message="CELERY_TASK_ALWAYS_EAGER is True — tasks run synchronously; disable in production",
                        setting="CELERY_TASK_ALWAYS_EAGER",
                    )
                )
            if _BROKER_URL_RE.search(line):
                if _REDIS_NO_AUTH_RE.search(line):
                    findings.append(
                        InsecureCelerySettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="unauthenticated_redis_broker",
                            severity="high",
                            message="Celery broker/backend uses Redis without authentication",
                        )
                    )
                elif _AMQP_GUEST_RE.search(line):
                    findings.append(
                        InsecureCelerySettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="unauthenticated_amqp_broker",
                            severity="high",
                            message="Celery broker uses default or unauthenticated AMQP credentials",
                        )
                    )
        return findings

    def analyze(self) -> list[InsecureCelerySettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureCelerySettingsFinding] = []
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
        self._stats = InsecureCelerySettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureCelerySettingsStats:
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
            f"Insecure Celery settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Celery settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Celery configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
