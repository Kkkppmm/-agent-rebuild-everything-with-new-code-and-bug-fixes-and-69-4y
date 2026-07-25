"""Prompt templates and built-in developer prompts."""

from devai.prompts.dev_prompts import (
    CODE_REVIEW,
    DEBUG_ERROR,
    EXPLAIN_CODE,
    GENERATE_TESTS,
    REFACTOR,
    WRITE_DOCS,
)
from devai.prompts.template import PromptTemplate

__all__ = [
    "CODE_REVIEW",
    "DEBUG_ERROR",
    "EXPLAIN_CODE",
    "GENERATE_TESTS",
    "PromptTemplate",
    "REFACTOR",
    "WRITE_DOCS",
]
