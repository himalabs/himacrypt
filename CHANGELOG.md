# Changelog

[![Keep a Changelog](https://img.shields.io/badge/Keep%20a-Changelog-blue.svg)](https://keepachangelog.com/en/1.1.0/)
[![Semantic Versioning](https://img.shields.io/badge/Semantic-Versioning-brightgreen.svg)](https://semver.org/spec/v2.0.0.html)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## v0.1.1 - (2025-08-25)

### Added

- Core encryption primitives: AES-GCM content encryption and RSA-OAEP key wrapping implemented in `himacrypt/core.py` (Encryptor, encrypt_env_file, decrypt_env_file, encrypt_data/decrypt_data).
- RSA key generation helper and PEM writers: `generate_rsa_keypair`, `write_keypair_to_dir`.
- KeyProvider abstraction and a file-backed implementation: `himacrypt/key_provider.py` (`KeyProvider`, `FileKeyProvider`) with unit tests.
- Documentation: `docs/key_provider.md`, updates to `docs/api.md` and other API docs to reflect the new KeyProvider API.
- Added `KeyProvider` abstraction and `FileKeyProvider` implementation. Files: `himacrypt/key_provider.py`, `tests/test_key_provider.py`, `docs/key_provider.md`.
- Added secret rotation helper `rotate_keys` and `himacrypt rotate` CLI integration. Files: `himacrypt/core.py` (rotate_keys), `himacrypt/cli/arguments/rotate.py`, `tests/test_rotate.py`, `tests/test_cli_rotate.py`.

## v0.1.0 - (2025-08-01)

### Added

- `poetry.lock` file to lock dependency versions.
- `pyproject.toml` file for project configuration.
- Initial package structure with `himacrypt` and `tests` directories.
- Added `hello_world` function in `himacrypt/hello_world.py` that returns a simple "Hello, world!" string.
- Added test for `hello_world` in `tests/test_hello_world.py`.
- Github workflows `publish-package.yml` and `run-test.yml`.