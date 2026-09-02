"""Example: audit Pipenv Pipfile and Pipfile.lock with PipfileAnalyzer."""

from devai.pipfile_analyzer import PipfileAnalyzer

analyzer = PipfileAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo Pipenv configs found. Scaffold a hardened Pipfile snippet:")
    print(analyzer.generate_hardened_config())
