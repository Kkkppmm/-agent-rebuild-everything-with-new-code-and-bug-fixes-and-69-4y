"""Example: audit Hadolint configuration with DevAI."""

from pathlib import Path

from devai import DevAI

HADOLINT_CONFIG = """\
failure-threshold: warning
format: tty
ignored: []
"""


def main() -> None:
    root = Path(__file__).parent / "_hadolint_demo"
    root.mkdir(exist_ok=True)
    (root / ".hadolint.yaml").write_text(HADOLINT_CONFIG, encoding="utf-8")

    analyzer = DevAI.mock().hadolint(root)
    print(analyzer.summary())
    print(f"Health score: {analyzer.health_score()}/100")
    print()
    print(analyzer.to_context())


if __name__ == "__main__":
    main()
