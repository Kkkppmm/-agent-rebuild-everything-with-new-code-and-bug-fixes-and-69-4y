"""Compare code versions and detect project type with DevAI."""

from devai import DevAI, CodeComparer, ProjectDetector, PromptRegistry

# Compare two code versions
ai = DevAI.mock()
comparer = CodeComparer(ai.assistant)

result = comparer.compare(
    "def greet(name):\n    return 'Hello ' + name",
    "def greet(name: str) -> str:\n    return f'Hello {name}'",
)
print(result.diff)
print(f"Changed lines: {result.changed_lines}")

# AI review of changes
review = comparer.review_changes(
    "x = 1",
    "x = 2",
)
print(review)

# Detect project type
profile = ProjectDetector().detect(".")
print(profile.summary)
print(profile.to_context())

# Browse built-in prompts
registry = PromptRegistry()
print("Available prompts:", len(registry.list()))
print(registry.get("code_review").input_variables)

# Facade shortcuts
ai = DevAI.mock()
print(ai.detect_project(".").summary)
print(ai.compare("old code", "new code", review=True))
