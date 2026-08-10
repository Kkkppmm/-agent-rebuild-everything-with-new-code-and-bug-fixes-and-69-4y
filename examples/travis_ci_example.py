"""Example: audit Travis CI configs for security and CI best practices."""

from devai import TravisCIAnalyzer


def main() -> None:
    analyzer = TravisCIAnalyzer(".")
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")

    findings = analyzer.analyze()
    if findings:
        print("\nFindings:")
        for finding in findings[:10]:
            print(f"  {finding.format()}")
    else:
        print("\nNo Travis CI configs found or no issues detected.")


if __name__ == "__main__":
    main()
