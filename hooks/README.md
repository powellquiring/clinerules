# Hooks

This directory contains hooks, including a `PreToolUse.py` script that acts as a safeguard during agent tool use. It intercepts shell commands to block potentially unsafe state-changing operations (like `git commit`, `terraform apply`) or raw shell file I/O (like redirection and heredocs).

## Setup after a fresh Git clone

This project uses [uv](https://docs.astral.sh/uv/) for fast Python dependency management.

1. Ensure you have `uv` installed. If you don't have it, you can install it via:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
2. Navigate to this directory and sync the dependencies. This will automatically create the virtual environment (`.venv`) and install all required packages, including development tools like `pytest`:
   ```bash
   uv sync
   ```

## Running the Test Suite

The test suite ensures the `PreToolUse.py` hook correctly identifies and blocks restricted commands while allowing safe ones.

To run the full test suite, use:
```bash
uv run pytest
```

For more verbose output, run:
```bash
uv run pytest -v
```