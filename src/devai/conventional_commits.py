"""ConventionalCommitsValidator — lint commit messages against Conventional Commits."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

VALID_TYPES = (
    "feat",
    "fix",
    "docs",
    "style",
    "refactor",
    "perf",
    "test",
    "build",
    "ci",
    "chore",
    "revert",
)

HEADER_PATTERN = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s+(?P<description>.+)$"
)

BREAKING_FOOTER = re.compile(r"^BREAKING CHANGE:\s+", re.MULTILINE)


@dataclass
class CommitValidationResult:
    """Result of validating a commit message."""

    valid: bool
    message: str
    errors: list[str] = field(default_factory=list)
    commit_type: str | None = None
    scope: str | None = None
    breaking: bool = False
    description: str | None = None

    def format(self) -> str:
        """Return a human-readable validation result."""
        if self.valid:
            parts = [f"Valid conventional commit: {self.commit_type}"]
            if self.scope:
                parts.append(f"scope={self.scope}")
            if self.breaking:
                parts.append("breaking")
            return ", ".join(parts)
        return f"Invalid: {'; '.join(self.errors)}"


class ConventionalCommitsValidator:
    """Validate commit messages against the Conventional Commits specification.

    Supports optional scopes, breaking change markers (`!` or BREAKING CHANGE footer),
    and configurable allowed commit types.
    """

    def __init__(
        self,
        *,
        allowed_types: tuple[str, ...] | None = None,
        max_header_length: int = 100,
        require_scope: bool = False,
    ) -> None:
        self.allowed_types = allowed_types or VALID_TYPES
        self.max_header_length = max_header_length
        self.require_scope = require_scope

    def validate(self, message: str) -> CommitValidationResult:
        """Validate a commit message and return a structured result."""
        errors: list[str] = []
        stripped = message.strip()

        if not stripped:
            return CommitValidationResult(
                valid=False,
                message=message,
                errors=["Commit message is empty"],
            )

        lines = stripped.splitlines()
        header = lines[0]

        if len(header) > self.max_header_length:
            errors.append(
                f"Header exceeds {self.max_header_length} characters "
                f"({len(header)} chars)"
            )

        match = HEADER_PATTERN.match(header)
        if not match:
            errors.append(
                "Header must match: type(scope)!: description "
                "(e.g. feat(api): add endpoint)"
            )
            return CommitValidationResult(
                valid=False,
                message=message,
                errors=errors,
            )

        commit_type = match.group("type")
        scope = match.group("scope")
        breaking_marker = match.group("breaking") == "!"
        description = match.group("description").strip()

        if commit_type not in self.allowed_types:
            errors.append(
                f"Unknown type '{commit_type}'; "
                f"allowed: {', '.join(self.allowed_types)}"
            )

        if self.require_scope and not scope:
            errors.append("Scope is required but missing")

        if not description:
            errors.append("Description must not be empty")

        if description.endswith("."):
            errors.append("Description should not end with a period")

        breaking_footer = bool(BREAKING_FOOTER.search(stripped))
        breaking = breaking_marker or breaking_footer

        if len(lines) > 1 and lines[1].strip():
            errors.append(
                "Second line must be blank (separate header from body)"
            )

        return CommitValidationResult(
            valid=len(errors) == 0,
            message=message,
            errors=errors,
            commit_type=commit_type,
            scope=scope,
            breaking=breaking,
            description=description,
        )

    def validate_batch(self, messages: list[str]) -> list[CommitValidationResult]:
        """Validate multiple commit messages."""
        return [self.validate(m) for m in messages]

    def lint(self, message: str) -> str | None:
        """Return the first error string, or None if valid."""
        result = self.validate(message)
        if result.valid:
            return None
        return result.errors[0]
