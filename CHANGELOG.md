# Changelog

[![Keep a Changelog](https://img.shields.io/badge/Keep%20a-Changelog-blue.svg)](https://keepachangelog.com/en/1.1.0/)
[![Semantic Versioning](https://img.shields.io/badge/Semantic-Versioning-brightgreen.svg)](https://semver.org/spec/v2.0.0.html)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## v0.1.0 - (2025-08-01)

### Added

- `poetry.lock` file to lock dependency versions.
- `pyproject.toml` file for project configuration.
- Initial package structure with `himacrypt` and `tests` directories.
- Added `hello_world` function in `himacrypt/hello_world.py` that returns a simple "Hello, world!" string.
- Added test for `hello_world` in `tests/test_hello_world.py`.
- Github workflows `publish-package.yml` and `run-test.yml`.