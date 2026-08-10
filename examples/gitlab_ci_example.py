"""Example: audit GitLab CI configs for security and CI best practices."""

from devai import GitLabCIAnalyzer


def main() -> None:
    analyzer = GitLabCIAnalyzer(".")
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")

    findings = analyzer.analyze()
    if findings:
        print("\nFindings:")
        for finding in findings[:10]:
            print(f"  {finding.format()}")
    else:
        print("\nNo GitLab CI configs found or no issues detected.")


if __name__ == "__main__":
    main()
