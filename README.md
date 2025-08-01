# himacrypt

[![Python](https://img.shields.io/pypi/pyversions/himacrypt.svg)](https://pypi.org/project/himacrypt/)
[![PyPI version](https://badge.fury.io/py/himacrypt.svg)](https://badge.fury.io/py/himacrypt)
[![License](https://img.shields.io/github/license/himalabs/himacrypt.svg)](https://github.com/himalabs/himacrypt/blob/main/LICENSE)
[![Tests](https://github.com/himalabs/himacrypt/workflows/tests/badge.svg)](https://github.com/himalabs/himacrypt/actions?query=workflow%3Atests)

A Python CLI tool and package to securely encrypt and manage environment variables for local development and deployments.

## Features

- 🔐 Secure encryption of environment variables
- 🛠️ Command-line interface for easy management
- 📦 Python package for programmatic usage
- 🔄 Simple integration with development workflows
- 🚀 Support for multiple deployment environments

## Installation

Install using pip:

```bash
pip install himacrypt
```

Or install using poetry:

```bash
poetry add himacrypt
```

## Usage

### Command Line Interface

```bash
# Encrypt environment variables
himacrypt encrypt .env -o .env.encrypted

# Decrypt environment variables
himacrypt decrypt .env.encrypted -o .env

# View encrypted file contents (safely)
himacrypt view .env.encrypted
```

### Python Package

```python
from himacrypt import Encryptor

# Initialize the encryptor
encryptor = Encryptor()

# Encrypt environment variables
encrypted_data = encryptor.encrypt_env_file('.env')

# Decrypt environment variables
decrypted_data = encryptor.decrypt_env_file('.env.encrypted')
```

## Documentation

For detailed documentation, please visit our [documentation site](https://himalabs.github.io/himacrypt/).

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For information about security policies and procedures, please refer to our [Security Policy](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
