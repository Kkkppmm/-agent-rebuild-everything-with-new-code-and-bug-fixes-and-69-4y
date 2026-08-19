"""Example: audit Maven pom.xml and settings.xml with MavenAnalyzer."""

from devai.maven_analyzer import MavenAnalyzer

analyzer = MavenAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("\nNo Maven configs found. Scaffold a hardened settings snippet:")
    print(analyzer.generate_hardened_config())
