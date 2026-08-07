"""InsecureCspSettingsAnalyzer — detect insecure Content Security Policy configuration."""

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
        "csp.py",
        "security.py",
    }
)
_CSP_DIRECTIVE_RE = re.compile(
    r"(CSP_(?:DEFAULT|SCRIPT|STYLE|IMG|FONT|CONNECT|FRAME|OBJECT|MEDIA|WORKER|CHILD)_SRC|"
    r"CONTENT_SECURITY_POLICY|CSP_POLICY)\s*=",
    re.IGNORECASE,
)
_UNSAFE_INLINE_RE = re.compile(r"['\"]unsafe-inline['\"]|unsafe-inline", re.IGNORECASE)
_UNSAFE_EVAL_RE = re.compile(r"['\"]unsafe-eval['\"]|unsafe-eval", re.IGNORECASE)
_WILDCARD_SRC_RE = re.compile(r"['\"]\*['\"]|['\"]https?:\*['\"]|default-src\s+\*", re.IGNORECASE)
_DATA_SCRIPT_RE = re.compile(
    r"(CSP_SCRIPT_SRC|script-src).*(['\"]data:['\"]|data:)",
    re.IGNORECASE,
)
_REPORT_ONLY_RE = re.compile(
    r"CSP_REPORT_ONLY\s*=\s*(True|1|['\"]1['\"])",
    re.IGNORECASE,
)
_CSP_DISABLED_RE = re.compile(
    r"(CSP_ENABLED|ENABLE_CSP|CONTENT_SECURITY_POLICY_ENABLED)\s*=\s*(False|0|['\"]0['\"])",
    re.IGNORECASE,
)
_CSP_HEADER_RE = re.compile(
    r"Content-Security-Policy['\"]?\s*[:=]\s*['\"].*(unsafe-inline|unsafe-eval|\*)",
    re.IGNORECASE,
)


@dataclass
class InsecureCspSettingsFinding:
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
class InsecureCspSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_csp_directive(name: str) -> bool:
    upper = name.upper()
    if upper.startswith("CSP_") and upper.endswith("_SRC"):
        return True
    return upper in {"CONTENT_SECURITY_POLICY", "CSP_POLICY"}


def _check_csp_value(
    value: str,
    lineno: int,
    setting: str,
    findings: list[InsecureCspSettingsFinding],
    path: str,
) -> None:
    lower = value.lower()
    if "unsafe-inline" in lower:
        findings.append(
            InsecureCspSettingsFinding(
                path=path,
                lineno=lineno,
                pattern="csp_unsafe_inline",
                severity="high",
                message="'unsafe-inline' weakens CSP and enables XSS via inline scripts/styles",
                setting=setting,
            )
        )
    if "unsafe-eval" in lower:
        findings.append(
            InsecureCspSettingsFinding(
                path=path,
                lineno=lineno,
                pattern="csp_unsafe_eval",
                severity="high",
                message="'unsafe-eval' allows eval() and weakens CSP against script injection",
                setting=setting,
            )
        )
    if re.search(r"(?:^|\s)\*(?:\s|$)|['\"]\*['\"]", value):
        findings.append(
            InsecureCspSettingsFinding(
                path=path,
                lineno=lineno,
                pattern="csp_wildcard_source",
                severity="medium",
                message="Wildcard (*) CSP source allows loading resources from any origin",
                setting=setting,
            )
        )
    if "data:" in lower and ("script" in setting.lower() or "script-src" in lower):
        findings.append(
            InsecureCspSettingsFinding(
                path=path,
                lineno=lineno,
                pattern="csp_data_script_src",
                severity="high",
                message="data: in script-src allows inline script execution via data URIs",
                setting=setting,
            )
        )


class _InsecureCspSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureCspSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureCspSettingsFinding(
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
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            upper = name.upper()
            if upper in {"CSP_REPORT_ONLY"} and (
                _is_true(node.value)
                or (isinstance(node.value, ast.Constant) and node.value.value in {1, "1"})
            ):
                self._add(
                    node.lineno,
                    "csp_report_only",
                    "medium",
                    "CSP_REPORT_ONLY without enforcement CSP provides no XSS protection",
                    setting=name,
                )
            elif upper in {"CSP_ENABLED", "ENABLE_CSP", "CONTENT_SECURITY_POLICY_ENABLED"} and (
                _is_false(node.value)
                or (isinstance(node.value, ast.Constant) and node.value.value in {0, "0"})
            ):
                self._add(
                    node.lineno,
                    "csp_disabled",
                    "high",
                    "Content Security Policy is explicitly disabled",
                    setting=name,
                )
            elif _is_csp_directive(name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    _check_csp_value(
                        node.value.value, node.lineno, name, self.findings, self.path
                    )
                elif isinstance(node.value, (ast.List, ast.Tuple)):
                    combined = " ".join(
                        v for elt in node.value.elts if (v := _dict_string_value(elt))
                    )
                    if combined:
                        _check_csp_value(combined, node.lineno, name, self.findings, self.path)
                    for elt in node.value.elts:
                        val = _dict_string_value(elt)
                        if val:
                            _check_csp_value(val, node.lineno, name, self.findings, self.path)
        self.generic_visit(node)


class InsecureCspSettingsAnalyzer:
    """Detect insecure Content Security Policy configuration in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureCspSettingsFinding] = []
        self._stats: InsecureCspSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureCspSettingsFinding]:
        findings: list[InsecureCspSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureCspSettingsVisitor(rel, filename)
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
            if _CSP_DISABLED_RE.search(line):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csp_disabled",
                        severity="high",
                        message="Content Security Policy is explicitly disabled",
                    )
                )
            if _REPORT_ONLY_RE.search(line):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csp_report_only",
                        severity="medium",
                        message="CSP_REPORT_ONLY without enforcement CSP provides no XSS protection",
                    )
                )
            if _CSP_DIRECTIVE_RE.search(line):
                if _UNSAFE_INLINE_RE.search(line):
                    findings.append(
                        InsecureCspSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="csp_unsafe_inline",
                            severity="high",
                            message="'unsafe-inline' weakens CSP and enables XSS via inline scripts/styles",
                        )
                    )
                if _UNSAFE_EVAL_RE.search(line):
                    findings.append(
                        InsecureCspSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="csp_unsafe_eval",
                            severity="high",
                            message="'unsafe-eval' allows eval() and weakens CSP against script injection",
                        )
                    )
                if _WILDCARD_SRC_RE.search(line):
                    findings.append(
                        InsecureCspSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="csp_wildcard_source",
                            severity="medium",
                            message="Wildcard (*) CSP source allows loading resources from any origin",
                        )
                    )
            if _DATA_SCRIPT_RE.search(line):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csp_data_script_src",
                        severity="high",
                        message="data: in script-src allows inline script execution via data URIs",
                    )
                )
            if _CSP_HEADER_RE.search(line):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csp_weak_header",
                        severity="high",
                        message="Content-Security-Policy header contains unsafe directives",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureCspSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureCspSettingsFinding] = []
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
        self._stats = InsecureCspSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureCspSettingsStats:
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
            f"Insecure CSP settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure CSP settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Content Security Policy patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
