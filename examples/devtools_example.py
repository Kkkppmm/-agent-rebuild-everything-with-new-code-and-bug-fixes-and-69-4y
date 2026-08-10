"""DevAI developer tools — imports, secrets, and git changelog."""

from devai import GitChangelog, ImportGraph, SecretsScanner

# Analyze import dependencies
graph = ImportGraph(".")
print(graph.summary())
cycles = graph.find_cycles()
if cycles:
    print("Circular imports:", cycles[0])

# Scan for hardcoded secrets
scanner = SecretsScanner(".")
print(scanner.summary())

# Generate changelog from git history
changelog = GitChangelog(".")
commits = changelog.collect(max_count=20)
print(changelog.format_markdown(commits, version="3.2.0"))
