"""Tests for git context."""

from devai.git_context import GitContext


class TestGitContext:
    def test_is_repo(self):
        ctx = GitContext(".")
        assert ctx.is_repo()

    def test_to_context(self):
        ctx = GitContext(".")
        if ctx.is_repo():
            context = ctx.to_context(include_diff=False)
            assert "branch" in context
            assert "commit" in context

    def test_review_context(self):
        ctx = GitContext(".")
        text = ctx.review_context()
        if ctx.is_repo():
            assert "Branch:" in text
