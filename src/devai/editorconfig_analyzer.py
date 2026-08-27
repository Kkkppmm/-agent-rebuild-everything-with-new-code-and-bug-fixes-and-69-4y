"""EditorConfigAnalyzer — audit .editorconfig files for security and consistency risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (".editorconfig",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:[\"']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']?)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
SECTION_PATTERN = re.compile(r"^\s*\[([^\]]+)\]\s*$")
PROPERTY_PATTERN = re.compile(r"^([^#=]+?)\s*=\s*(.*)$")


@dataclass
class EditorConfigFinding:
    """A security or best-practice issue in an EditorConfig file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class EditorConfigInfo:
    """Parsed metadata about an EditorConfig file."""

    path: str
    lines: int = 0
    sections: list[str] = field(default_factory=list)
    has_root: bool = False
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class EditorConfigStats:
    """Aggregate EditorConfig analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class EditorConfigAnalyzer:
    """Audit .editorconfig files for security risks and editor consistency.

    Scans EditorConfig files for hardcoded secrets, insecure URLs, dangerous
    shell patterns, missing charset/end_of_line settings, and conflicting root
    declarations across nested configs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[EditorConfigFinding] | None = None
        self._stats: EditorConfigStats | None = None
        self._infos: list[EditorConfigInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return EditorConfig paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".editorconfig")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[EditorConfigFinding],
        info: EditorConfigInfo,
        current_section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return current_section

        section_match = SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(1).strip()
            if section not in info.sections:
                info.sections.append(section)
            return section

        prop_match = PROPERTY_PATTERN.match(stripped)
        if prop_match:
            key = prop_match.group(1).strip().lower()
            value = prop_match.group(2).strip()
            scoped_key = f"{current_section}:{key}" if current_section else key
            info.properties[scoped_key] = value

            if key == "root" and value.lower() == "true":
                info.has_root = True

            if key == "charset" and value.lower() not in ("utf-8", "utf-8-bom"):
                findings.append(
                    EditorConfigFinding(
                        kind="non_utf8_charset",
                        severity="low",
                        message="charset is not utf-8 — prefer utf-8 for cross-platform consistency",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if key == "end_of_line" and value.lower() not in ("lf", "unset"):
                findings.append(
                    EditorConfigFinding(
                        kind="inconsistent_line_endings",
                        severity="low",
                        message="end_of_line is not lf — mixed line endings can cause CI diffs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if key == "max_line_length" and value.isdigit() and int(value) > 500:
                findings.append(
                    EditorConfigFinding(
                        kind="excessive_max_line_length",
                        severity="low",
                        message="max_line_length exceeds 500 — very long lines hurt readability",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                EditorConfigFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in EditorConfig — remove secrets from editor configs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                EditorConfigFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in EditorConfig — rotate and use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                EditorConfigFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in EditorConfig — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                EditorConfigFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                EditorConfigFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in EditorConfig — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                EditorConfigFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in EditorConfig",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return current_section

    def _analyze_file(self, path: Path) -> tuple[list[EditorConfigFinding], EditorConfigInfo]:
        findings: list[EditorConfigFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, EditorConfigInfo(path=rel)

        info = EditorConfigInfo(path=rel, lines=len(raw_lines))
        current_section = ""
        for lineno, raw in enumerate(raw_lines, start=1):
            current_section = self._scan_line(
                raw.rstrip(), lineno, rel, findings, info, current_section
            )

        if not info.has_root and path == self.root / ".editorconfig":
            findings.append(
                EditorConfigFinding(
                    kind="missing_root",
                    severity="medium",
                    message="root = true missing in top-level .editorconfig — nested configs may conflict",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        global_props = {k: v for k, v in info.properties.items() if ":" not in k}
        section_props = {k.split(":", 1)[1]: v for k, v in info.properties.items() if ":" in k}
        combined = {**section_props, **global_props}
        if not any(k in combined for k in ("charset", "end_of_line", "indent_style")):
            findings.append(
                EditorConfigFinding(
                    kind="missing_baseline_settings",
                    severity="low",
                    message="no global charset, end_of_line, or indent_style — add baseline editor settings",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[EditorConfigFinding]:
        """Scan EditorConfig files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[EditorConfigFinding] = []
        infos: list[EditorConfigInfo] = []
        paths = self.config_files()

        root_configs = [p for p in paths if p.parent == self.root]
        if len(root_configs) > 1:
            findings.append(
                EditorConfigFinding(
                    kind="duplicate_root_config",
                    severity="medium",
                    message="multiple .editorconfig files at project root — consolidate to one file",
                    path=str(root_configs[0].relative_to(self.root)),
                    lineno=1,
                    line="",
                )
            )

        nested_roots = [p for p in paths if p.parent != self.root]
        for nested in nested_roots:
            try:
                text = nested.read_text(encoding="utf-8", errors="replace")
                if re.search(r"^\s*root\s*=\s*true\s*$", text, re.MULTILINE | re.IGNORECASE):
                    rel = str(nested.relative_to(self.root))
                    findings.append(
                        EditorConfigFinding(
                            kind="nested_root_true",
                            severity="medium",
                            message="nested .editorconfig declares root = true — only the top-level file should",
                            path=rel,
                            lineno=1,
                            line="",
                        )
                    )
            except OSError:
                pass

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = EditorConfigStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> EditorConfigStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[EditorConfigInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened EditorConfig template."""
        return """\
# EditorConfig helps maintain consistent coding styles
# https://editorconfig.org

root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{js,ts,tsx,jsx,json,yml,yaml}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false

[Makefile]
indent_style = tab
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "EditorConfig: no config files found"
        return (
            f"EditorConfig: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "EditorConfig analysis:",
            self.summary(),
            f"Health score: {self.health_score()}",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        if stats.config_files == 0:
            lines.append("No EditorConfig files found.")
        return "\n".join(lines)
