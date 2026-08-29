"""Example: audit Remix configuration for security risks."""

from devai import DevAI

if __name__ == "__main__":
    analyzer = DevAI.mock().remix(".")
    print(analyzer.summary())
    print()
    print(analyzer.to_context())
