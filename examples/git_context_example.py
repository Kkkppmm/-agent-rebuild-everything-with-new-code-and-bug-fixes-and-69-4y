"""Git-aware AI reviews with DevAI."""

from devai import GitContext, quickstart

runtime = quickstart(use_mock=True)

# Review unstaged changes (requires a git repo)
# print(runtime.review_git())

# Or use GitContext directly
ctx = GitContext.staged_changes()
summary = ctx.summarize()
print(f"Changed files: {summary['files']}")

# Generate a commit message from staged changes
# print(ctx.commit_message(runtime.assistant))
