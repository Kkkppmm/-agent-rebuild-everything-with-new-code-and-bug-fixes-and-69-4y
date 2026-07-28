"""Built-in DevAI program presets for common developer workflows."""

from __future__ import annotations

from typing import Any

from devai.assistant import CodeAssistant
from devai.program import DevProgram

PRESET_DEFINITIONS: dict[str, dict[str, Any]] = {
    "pre-commit": {
        "name": "pre-commit",
        "description": "Review, security scan, and type hints before committing",
        "tasks": [
            {"name": "review", "action": "review"},
            {"name": "security", "action": "security"},
            {"name": "type_hints", "action": "type_hints"},
        ],
    },
    "release": {
        "name": "release",
        "description": "Full release checklist: review, security, performance, architecture",
        "tasks": [
            {"name": "review", "action": "review"},
            {"name": "security", "action": "security"},
            {"name": "performance", "action": "performance"},
            {"name": "architecture", "action": "architecture"},
        ],
    },
    "onboarding": {
        "name": "onboarding",
        "description": "Help new developers understand a module",
        "tasks": [
            {"name": "explain", "action": "explain"},
            {"name": "architecture", "action": "architecture"},
            {"name": "docstring", "action": "docstring"},
        ],
    },
    "security-deep-dive": {
        "name": "security-deep-dive",
        "description": "Thorough security and dependency audit",
        "tasks": [
            {"name": "security", "action": "security"},
            {"name": "deps", "action": "audit_deps", "input_key": "dependencies"},
            {"name": "dockerfile", "action": "dockerfile", "input_key": "dockerfile"},
        ],
    },
    "pr-review": {
        "name": "pr-review",
        "description": "Review a pull request diff for regressions and risks",
        "tasks": [
            {"name": "diff_review", "action": "review_diff", "input_key": "diff"},
            {"name": "security", "action": "security", "input_key": "code"},
            {"name": "performance", "action": "performance", "input_key": "code"},
        ],
    },
    "refactor-prep": {
        "name": "refactor-prep",
        "description": "Prepare for refactoring: explain, review, generate tests",
        "tasks": [
            {"name": "explain", "action": "explain"},
            {"name": "review", "action": "review"},
            {"name": "tests", "action": "tests"},
        ],
    },
    "ci-gate": {
        "name": "ci-gate",
        "description": "CI gate: review, security, performance, and type hints",
        "tasks": [
            {"name": "review", "action": "review"},
            {"name": "security", "action": "security"},
            {"name": "performance", "action": "performance"},
            {"name": "type_hints", "action": "type_hints"},
        ],
    },
    "incident-response": {
        "name": "incident-response",
        "description": "Triage incidents and analyze related logs",
        "tasks": [
            {
                "name": "triage",
                "action": "incident_triage",
                "input_key": "symptoms",
                "kwargs": {"logs": "$logs"},
            },
            {"name": "logs", "action": "analyze_logs", "input_key": "logs"},
        ],
    },
    "dependency-update": {
        "name": "dependency-update",
        "description": "Audit and recommend dependency upgrades",
        "tasks": [
            {"name": "audit", "action": "audit_deps", "input_key": "dependencies"},
            {
                "name": "upgrade",
                "action": "dependency_upgrade",
                "input_key": "dependencies",
            },
        ],
    },
    "docs-gen": {
        "name": "docs-gen",
        "description": "Generate documentation: explain, docstrings, and README outline",
        "tasks": [
            {"name": "explain", "action": "explain"},
            {"name": "docstring", "action": "docstring"},
            {
                "name": "readme",
                "action": "readme",
                "input_key": "project",
                "kwargs": {"description": "$description"},
            },
        ],
    },
    "test-gen": {
        "name": "test-gen",
        "description": "Generate tests: explain code, review, then write tests",
        "tasks": [
            {"name": "explain", "action": "explain"},
            {"name": "review", "action": "review"},
            {"name": "tests", "action": "tests"},
        ],
    },
    "hotfix": {
        "name": "hotfix",
        "description": "Fast hotfix gate: review, security scan, and regression tests",
        "tasks": [
            {"name": "review", "action": "review"},
            {"name": "security", "action": "security"},
            {"name": "tests", "action": "tests"},
        ],
    },
}


def list_presets() -> list[dict[str, str]]:
    """Return metadata for all built-in presets."""
    return [
        {
            "name": definition["name"],
            "description": definition["description"],
        }
        for definition in PRESET_DEFINITIONS.values()
    ]


def get_preset(name: str, assistant: CodeAssistant) -> DevProgram:
    """Load a built-in program preset by name."""
    key = name.lower().replace("_", "-")
    if key not in PRESET_DEFINITIONS:
        available = ", ".join(sorted(PRESET_DEFINITIONS))
        raise ValueError(f"Unknown preset '{name}'. Available: {available}")
    return DevProgram.from_dict(PRESET_DEFINITIONS[key], assistant)
