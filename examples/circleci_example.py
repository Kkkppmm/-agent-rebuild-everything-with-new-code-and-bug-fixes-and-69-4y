"""Example: audit CircleCI configs for security and CI best practices."""

from devai import CircleCIAnalyzer


def main() -> None:
    analyzer = CircleCIAnalyzer(".")
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")

    findings = analyzer.analyze()
    if findings:
        print("\nFindings:")
        for finding in findings[:10]:
            print(f"  {finding.format()}")
    else:
        print("\nNo CircleCI configs found or no issues detected.")

    print("\n--- Hardened template ---")
    print(analyzer.generate_hardened_template())


if __name__ == "__main__":
    main()
