"""Structured output schemas for DevAI developer workflows."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CodeIssue(BaseModel):
    """A single issue found during code review."""

    severity: str = Field(description="low, medium, high, or critical")
    line: int | None = None
    message: str
    suggestion: str | None = None


class CodeReviewResult(BaseModel):
    """Structured code review output."""

    summary: str
    score: int = Field(ge=1, le=10)
    issues: list[CodeIssue] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    """A security vulnerability finding."""

    severity: str
    category: str = Field(description="e.g. injection, auth, crypto, secrets")
    description: str
    remediation: str | None = None


class SecurityAuditResult(BaseModel):
    """Structured security audit output."""

    summary: str
    risk_level: str = Field(description="low, medium, high, or critical")
    findings: list[SecurityFinding] = Field(default_factory=list)


class PerfIssue(BaseModel):
    """A performance issue."""

    area: str = Field(description="e.g. algorithm, memory, I/O, concurrency")
    impact: str = Field(description="low, medium, or high")
    description: str
    fix: str | None = None


class PerfReviewResult(BaseModel):
    """Structured performance review output."""

    summary: str
    issues: list[PerfIssue] = Field(default_factory=list)
