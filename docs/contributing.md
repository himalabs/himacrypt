# Contributing to himacrypt

Thank you for considering contributing to himacrypt! This guide explains how to set up a development environment, run tests, and follow the project's coding standards.

## Getting started

1. Fork the repository and clone your fork.
2. Create a new branch for your change (feature/bugfix). Use a descriptive branch name.
3. Install dependencies:

```bash
poetry install
```

4. Run tests locally:

```bash
poetry run pytest -q
```

## Code style and checks

- Use `black` for formatting. The Makefile provides `make format`.
- Use `ruff` for linting; the Makefile provides `make lint` and `make lint-fix`.
- Type-checking is enforced with `mypy` in strict mode. Run `make typecheck` and fix issues.

## Testing

- Add unit tests under the `tests/` directory.
- Tests should be deterministic and avoid network or filesystem side-effects where possible.
- Use `tmp_path` fixture for temporary filesystem operations.

## Pull requests

- Keep PRs small and focused.
- Include tests for new features or bug fixes.
- Update documentation if you change user-facing behavior.
- Connect your PR to an issue when possible and provide reproducible steps.

## Security

- Do not commit secrets or private keys to the repository.
- If you find a security issue, follow the responsible disclosure policy in `SECURITY.md`.

Welcome — maintainers will review PRs and provide feedback; be prepared to make iterative changes.
