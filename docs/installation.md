# Installation

This page covers installing himacrypt for both end-users and developers.

Table of Contents
- Prerequisites
- Install from PyPI (end users)
- Install for development (Poetry)
- Windows-specific notes
- Docker usage
- Verifying the installation

## Prerequisites

- Python 3.10 or newer is required (the project targets 3.10+).
- `pip` or `poetry` depending on your installation preference.
- Recommended (for development): `poetry` to manage virtual environments and dev dependencies.

## Install from PyPI (End users)

The easiest way to install himacrypt for use is via PyPI:

```bash
pip install himacrypt
```

This installs the CLI entry point and the library into your Python environment.

## Install for development (Poetry)

If you want to work on the project locally (run tests, modify code), use Poetry:

```bash
git clone https://github.com/himalabs/himacrypt.git
cd himacrypt
poetry install
```

This installs the project dependencies and dev dependencies and creates an isolated virtual environment.

To run the CLI from the project root while the virtual environment is active:

```bash
poetry run himacrypt --help
```

## Windows-specific notes

- On Windows, `make` is typically not available. Use the Makefile targets by running the underlying commands via `poetry run` or install a compatible `make` tool (e.g., via Chocolatey).
- When running PowerShell, you can run tests with:

```powershell
poetry run pytest -q
```

- File permission utilities such as `chmod` are not available on Windows in the same way as UNIX. The project assumes secure handling of key files; on Windows use NTFS file permissions and credential stores.

## Docker usage

A Docker image or containerized workflow is recommended for reproducible CI runs. Example Dockerfile snippet for local quick tests:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --upgrade pip && pip install poetry && poetry install --no-dev
ENTRYPOINT ["himacrypt"]
```

When using Docker in CI, mount secrets (private keys) at runtime rather than baking them into images.

## Verifying the installation

1. Run the help command to ensure the CLI is registered:

```bash
poetry run himacrypt --help
# or, if installed system-wide
himacrypt --help
```

2. Run a quick command to ensure subcommands load (this only verifies the CLI wiring):

```bash
poetry run himacrypt keygen --out ./keys --key-size 2048 --force
```

This should create `./keys/public.pem` and `./keys/private.pem` (if key generation logic is implemented) or return a graceful message if the functionality is a TODO.

---

If anything fails during installation, capture the error message and consult the `FAQ` or open an issue with the failure details and environment information (OS, Python version, Poetry/pip version).
