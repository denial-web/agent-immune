# Contributing to agent-immune

Thanks for your interest in contributing! This project welcomes bug reports, feature requests, and pull requests.

## Getting started

```bash
git clone https://github.com/denial-web/agent-immune.git
cd agent-immune
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"
pytest
```

Requires Python 3.10+ for the full test suite (MCP tests skip on 3.9).

## Running tests

```bash
pytest                          # full suite with coverage
pytest tests/test_immune.py -v  # single module
pytest --no-cov -q              # quick run without coverage
```

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

Line length is 120 characters. Target is Python 3.11+.

## Pull request process

1. Fork the repo and create a branch from `main`.
2. Add tests for any new functionality.
3. Make sure `pytest` and `ruff check` pass.
4. Keep commits focused — one logical change per commit.
5. Open a PR against `main` with a clear description of what and why.

## Reporting bugs

Open a [GitHub issue](https://github.com/denial-web/agent-immune/issues/new) with:

- What you expected vs. what happened
- Minimal reproduction steps
- Python version and OS

## Security vulnerabilities

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
