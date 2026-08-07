"""InsecureCspSettingsAnalyzer — detect weak Content-Security-Policy configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SETTINGS_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "security.py",
        "middleware.py",
        "talisman.py",
    }
)
_CSP_DIRECTIVE_PREFIXES = (
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "object-src",
    "media-src",
    "frame-src",
    "worker-src",
    "child-src",
    "form-action",
    "frame-ancestors",
    "base-uri",
)
_CSP_SETTING_RE = re.compile(
    r"(CSP_[A-Z_]+|CONTENT_SECURITY_POLICY|SECURE_CONTENT_SECURITY_POLICY|"
    r"content_security_policy|CONTENT_SECURITY_POLICY_REPORT_ONLY)",
    re.IGNORECASE,
)
_UNSAFE_INLINE_RE = re.compile(r"['\"]unsafe-inline['\"]|unsafe-inline", re.IGNORECASE)
_UNSAFE_EVAL_RE = re.compile(r"['\"]unsafe-eval['\"]|unsafe-eval", re.IGNORECASE)
_WILDCARD_DIRECTIVE_RE = re.compile(
    r"(default-src|script-src|style-src|connect-src|img-src|object-src|"
    r"frame-src|worker-src|child-src|form-action|base-uri)\s+[^;]*\*",
    re.IGNORECASE,
)
_WILDCARD_CSP_VALUE_RE = re.compile(
    r"(CSP_[A-Z_]+|CONTENT_SECURITY_POLICY)\s*=\s*.*['\"]\*['\"]",
    re.IGNORECASE,
)
_CSP_DISABLED_RE = re.compile(
    r"(CSP_ENABLED|SECURE_CONTENT_SECURITY_POLICY)\s*=\s*False|"
    r"CSP_DEFAULT_SRC\s*=\s*None|CONTENT_SECURITY_POLICY\s*=\s*\{\s*\}",
    re.IGNORECASE,
)
_REPORT_ONLY_RE = re.compile(
    r"Content-Security-Policy-Report-Only|CONTENT_SECURITY_POLICY_REPORT_ONLY|"
    r"content_security_policy_report_only|CSP_REPORT_ONLY",
    re.IGNORECASE,
)
_ENFORCEMENT_CSP_RE = re.compile(
    r"Content-Security-Policy(?!-Report-Only)|CONTENT_SECURITY_POLICY(?!_REPORT_ONLY)|"
    r"SECURE_CONTENT_SECURITY_POLICY|CSP_DEFAULT_SRC|CSP_SCRIPT_SRC",
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


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _iter_string_values(node: ast.AST) -> list[str]:
    values: list[str] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        values.append(node.value)
    elif isinstance(node, ast.Tuple) or isinstance(node, ast.List):
        for elt in node.elts:
            values.extend(_iter_string_values(elt))
    elif isinstance(node, ast.Dict):
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key:
                values.append(key)
            values.extend(_iter_string_values(value_node))
    return values


class _InsecureCspSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureCspSettingsFinding] = []
        self._has_enforcement_csp = False
        self._has_report_only_csp = False

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

    def _scan_csp_values(self, lineno: int, values: list[str], setting: str) -> None:
        joined = " ".join(values)
        if _UNSAFE_INLINE_RE.search(joined):
            self._add(
                lineno,
                "unsafe_inline",
                "high",
                "CSP allows 'unsafe-inline' — remove inline script/style allowances and use nonces or hashes",
                setting=setting,
            )
        if _UNSAFE_EVAL_RE.search(joined):
            self._add(
                lineno,
                "unsafe_eval",
                "high",
                "CSP allows 'unsafe-eval' — avoid eval() and inline script execution in production",
                setting=setting,
            )
        if any(value.strip() == "*" for value in values):
            self._add(
                lineno,
                "wildcard_source",
                "high",
                "CSP directive uses wildcard (*) source — restrict to specific trusted origins",
                setting=setting,
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            upper = name.upper()

            if upper in {"CSP_ENABLED", "SECURE_CONTENT_SECURITY_POLICY"} and _is_false(node.value):
                self._add(
                    node.lineno,
                    "csp_disabled",
                    "high",
                    f"{name} disables Content-Security-Policy enforcement",
                    setting=name,
                )
            elif upper == "CSP_DEFAULT_SRC" and _is_none(node.value):
                self._add(
                    node.lineno,
                    "csp_disabled",
                    "medium",
                    "CSP_DEFAULT_SRC is None — Content-Security-Policy may not be enforced",
                    setting=name,
                )
            elif upper.startswith("CSP_") or upper in {
                "CONTENT_SECURITY_POLICY",
                "SECURE_CONTENT_SECURITY_POLICY",
            }:
                self._has_enforcement_csp = True
                values = _iter_string_values(node.value)
                self._scan_csp_values(node.lineno, values, name)
            elif "REPORT_ONLY" in upper or upper.endswith("_REPORT_ONLY"):
                self._has_report_only_csp = True

        self.generic_visit(node)

    def finalize(self) -> None:
        if self._has_report_only_csp and not self._has_enforcement_csp:
            self._add(
                1,
                "report_only_mode",
                "medium",
                "Only Content-Security-Policy-Report-Only is configured — enforce CSP in production",
                setting="Content-Security-Policy-Report-Only",
            )


class InsecureCspSettingsAnalyzer:
    """Detect weak Content-Security-Policy settings in Django, Flask, and middleware configs."""

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

    def _scan_source(self, rel: str, source: str, filename: str) -> list[InsecureCspSettingsFinding]:
        findings: list[InsecureCspSettingsFinding] = []
        has_enforcement = False
        has_report_only = False

        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureCspSettingsVisitor(rel, filename)
            visitor.visit(tree)
            visitor.finalize()
            findings.extend(visitor.findings)
            has_enforcement = visitor._has_enforcement_csp
            has_report_only = visitor._has_report_only_csp
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if not (
                filename in _SETTINGS_FILENAMES
                or _CSP_SETTING_RE.search(line)
                or "Content-Security-Policy" in line
            ):
                continue

            if _ENFORCEMENT_CSP_RE.search(line) and not _REPORT_ONLY_RE.search(line):
                has_enforcement = True
            if _REPORT_ONLY_RE.search(line):
                has_report_only = True

            if _UNSAFE_INLINE_RE.search(line) and (
                "csp" in line.lower() or "content-security" in line.lower() or "src" in line.lower()
            ):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="unsafe_inline",
                        severity="high",
                        message="CSP allows 'unsafe-inline' — remove inline script/style allowances and use nonces or hashes",
                        setting="CSP",
                    )
                )
            if _UNSAFE_EVAL_RE.search(line) and (
                "csp" in line.lower() or "content-security" in line.lower() or "src" in line.lower()
            ):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="unsafe_eval",
                        severity="high",
                        message="CSP allows 'unsafe-eval' — avoid eval() and inline script execution in production",
                        setting="CSP",
                    )
                )
            if _WILDCARD_DIRECTIVE_RE.search(line) or _WILDCARD_CSP_VALUE_RE.search(line):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="wildcard_source",
                        severity="high",
                        message="CSP directive uses wildcard (*) source — restrict to specific trusted origins",
                        setting="CSP",
                    )
                )
            if _CSP_DISABLED_RE.search(line):
                findings.append(
                    InsecureCspSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csp_disabled",
                        severity="high",
                        message="Content-Security-Policy enforcement is disabled",
                        setting="CSP",
                    )
                )

        if has_report_only and not has_enforcement:
            findings.append(
                InsecureCspSettingsFinding(
                    path=rel,
                    lineno=1,
                    pattern="report_only_mode",
                    severity="medium",
                    message="Only Content-Security-Policy-Report-Only is configured — enforce CSP in production",
                    setting="Content-Security-Policy-Report-Only",
                )
            )

        # Deduplicate by lineno + pattern
        seen: set[tuple[int, str]] = set()
        unique: list[InsecureCspSettingsFinding] = []
        for finding in findings:
            key = (finding.lineno, finding.pattern)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

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
            lines.append("No weak Content-Security-Policy patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
