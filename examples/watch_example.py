"""Example: watch a directory and auto-review on file changes."""

from devai import DevRuntime, DevWatcher

runtime = DevRuntime.create(use_mock=True)

watcher = DevWatcher(
    "src/",
    patterns=["*.py"],
    runtime=runtime,
    preset="pre-commit",
)

# Process any existing files once
watcher.run_once()

# Poll for one change (demo — use watch() in production loops)
print("Watching for changes... (modify a .py file in src/)")
results = watcher.watch(interval=1.0, max_events=1, timeout=30.0)

for result in results:
    if result.success:
        print(f"Reviewed {result.event.path}")
    else:
        print(f"Error: {result.error}")
