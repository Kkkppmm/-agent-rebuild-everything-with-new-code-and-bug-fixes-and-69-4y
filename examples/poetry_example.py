"""Example: audit Poetry pyproject.toml and poetry.toml with PoetryAnalyzer."""

from devai.poetry_analyzer import PoetryAnalyzer

analyzer = PoetryAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo Poetry configs found. Scaffold a hardened poetry.toml snippet:")
    print(analyzer.generate_hardened_config())
