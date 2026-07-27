"""Prompt module for DevAI."""

from devai.prompts.template import PromptTemplate
from devai.prompts.dev_prompts import (
    CODE_REVIEW,
    DEBUG,
    COMMIT_MESSAGE,
    API_DESIGN,
    SECURITY_REVIEW,
    SQL_OPTIMIZE,
    README_GEN,
    TYPE_HINTS,
    REGEX_BUILD,
    LOG_ANALYSIS,
    REFACTOR,
    EXPLAIN_CODE,
    TEST_GEN,
)

__all__ = [
    "PromptTemplate",
    "CODE_REVIEW",
    "DEBUG",
    "COMMIT_MESSAGE",
    "API_DESIGN",
    "SECURITY_REVIEW",
    "SQL_OPTIMIZE",
    "README_GEN",
    "TYPE_HINTS",
    "REGEX_BUILD",
    "LOG_ANALYSIS",
    "REFACTOR",
    "EXPLAIN_CODE",
    "TEST_GEN",
]
