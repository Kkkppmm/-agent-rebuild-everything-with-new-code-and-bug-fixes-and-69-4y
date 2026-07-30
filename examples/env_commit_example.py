"""Example: environment variable scanning and commit message linting."""

from devai import ConventionalCommitsValidator, EnvVarScanner

# Scan a project for env var usage vs .env alignment
scanner = EnvVarScanner(".")
print(scanner.summary())
for issue in scanner.scan():
    print(f"  {issue.format()}")

# Lint a commit message
validator = ConventionalCommitsValidator()
messages = [
    "feat(api): add user registration",
    "bad commit message",
    "fix!: remove deprecated endpoint",
]
for msg in messages:
    result = validator.validate(msg)
    print(f"{msg!r} -> {result.format()}")
