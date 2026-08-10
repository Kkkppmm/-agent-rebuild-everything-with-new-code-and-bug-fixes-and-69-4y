"""Example: audit Jenkinsfiles for security and CI best practices."""

from devai import JenkinsAnalyzer


def main() -> None:
    analyzer = JenkinsAnalyzer(".")
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")

    findings = analyzer.analyze()
    if findings:
        print("\nFindings:")
        for finding in findings[:10]:
            print(f"  {finding.format()}")
    else:
        print("\nNo Jenkinsfiles found or no issues detected.")


if __name__ == "__main__":
    main()
