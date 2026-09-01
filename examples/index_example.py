"""Example: index and search Python symbols in a project."""

from devai import CodeSymbolIndex

index = CodeSymbolIndex(".")
print(index.summary())

for symbol in index.search("DevAI"):
    print(f"[{symbol.kind}] {symbol.qualified_name()} @ {symbol.path}:{symbol.lineno}")

print()
print(index.to_context("assistant", max_symbols=10))
