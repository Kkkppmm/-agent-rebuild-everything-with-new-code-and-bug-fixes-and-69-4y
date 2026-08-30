"""Example: audit Gradle build files with GradleAnalyzer."""

from devai.gradle_analyzer import GradleAnalyzer

analyzer = GradleAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo Gradle configs found. Scaffold a hardened config:")
    print(analyzer.generate_hardened_config())
