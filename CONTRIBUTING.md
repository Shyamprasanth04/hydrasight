# Contributing to HydraSight

First off, thank you for considering contributing to HydraSight! It's people like you that make open-source security tools better.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [How Can I Contribute?](#how-can-i-contribute)
3. [Development Environment Setup](#development-environment-setup)
4. [Coding Standards](#coding-standards)
5. [Pull Request Process](#pull-request-process)

## Code of Conduct

This project and everyone participating in it is governed by the [HydraSight Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

*   **Reporting Bugs:** Use the GitHub Issue Tracker. Please use the provided Bug Report template and provide clear steps to reproduce.
*   **Suggesting Enhancements:** Open an issue using the Feature Request template. Explain *why* the enhancement would be useful and how it fits into the overall architecture.
*   **Code Contributions:** We welcome Pull Requests for bug fixes, new features, or new tool integrations. See the [Project Context](PROJECT_CONTEXT.md) for a guide on "Adding a New Tool Action".

## Development Environment Setup

1.  **Fork the repo** and clone it locally.
2.  **Install in editable mode with development dependencies:**
    ```bash
    pip install -e ".[dev]"
    ```
3.  **Run the test suite** to ensure everything is working:
    ```bash
    pytest tests/ -v --tb=short
    ```
    *Note: The test suite runs entirely locally using mocks. It does not require Ollama or the Kali MCP server to be running.*

## Coding Standards

We enforce strict coding standards to keep the codebase clean and maintainable. Your code must pass all checks before a PR can be merged.

We use `ruff`, `mypy`, `pylint`, and `black`. You can run these manually:

```bash
# Auto-format code
black hydrasight/ tests/
ruff check hydrasight/ tests/ --fix

# Type checking
mypy hydrasight/ --ignore-missing-imports

# Run pylint (we aim for > 9.0)
pylint hydrasight/
```

Our CI pipeline will automatically run these checks on every Pull Request.

## Pull Request Process

1.  Create a new branch for your feature or bugfix (`git checkout -b feature/my-new-feature`).
2.  Make your changes.
3.  **Write Tests:** If you are adding a new feature or fixing a bug, please write corresponding tests in the `tests/` directory. Ensure `pytest tests/` passes.
4.  Run the linters locally.
5.  Commit your changes using clear and descriptive commit messages.
6.  Push to your fork and submit a Pull Request.
7.  Fill out the PR template completely.
8.  A maintainer will review your PR, request changes if necessary, and merge it once approved.
