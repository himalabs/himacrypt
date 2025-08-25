# 🔐 himacrypt

[![Python](https://img.shields.io/pypi/pyversions/himacrypt.svg)](https://pypi.org/project/himacrypt/)
[![PyPI version](https://badge.fury.io/py/himacrypt.svg)](https://badge.fury.io/py/himacrypt)
[![License](https://img.shields.io/github/license/himalabs/himacrypt.svg)](https://github.com/himalabs/himacrypt/blob/main/LICENSE)
[![Tests](https://github.com/himalabs/himacrypt/workflows/tests/badge.svg)](https://github.com/himalabs/himacrypt/actions?query=workflow%3Atests)


**Secure your environment files with asymmetric encryption.**
`himacrypt` is a Python CLI tool and library that lets you encrypt `.env`, `.json`, `.yaml`, and `.toml` files using RSA/hybrid encryption to safely store and manage secrets in your repositories or deployments.

---

## ⚙️ Features

- ✅ **Asymmetric encryption** using RSA (public/private key)
- 🔁 **Hybrid encryption** (AES + RSA) for performance and security
- 🧪 **Validate and lint** `.env` files
- 🧩 Supports `.env`, `.yaml`, `.json`, `.toml` formats
- 🔐 **Field-level encryption** (only encrypt selected keys)
- 🧱 Python package with **CLI + API** support
- 🐳 **Docker/CI/CD ready** (auto-decrypt at runtime)
- 🛠 Git pre-commit hook to prevent accidental `.env` leaks
- 📦 Future integration with AWS KMS, GCP KMS, Vault

---

## 🚀 Installation

```bash
pip install himacrypt
```
Or for local development with Poetry:

```bash
git clone https://github.com/yourusername/himacrypt.git
cd himacrypt
poetry install
```
## 🔧 Getting Started

### 🔑 1. Generate RSA Key Pair

```bash
himacrypt keygen --out ./keys/
```

Creates:
- `keys/public.pem` – share this
- `keys/private.pem` – keep this secret

### 🔒 2. Encrypt Your .env File

```bash
himacrypt encrypt \
  --in .env \
  --out .env.enc \
  --public-key ./keys/public.pem
```
### 🔓 3. Decrypt Encrypted File

```bash
himacrypt decrypt \
  --in .env.enc \
  --out .env \
  --private-key ./keys/private.pem
```

## 🧰 Additional Commands

### 🧪 Lint .env File

```bash
himacrypt lint --in .env
```
Warns on:
- Missing keys
- Unsafe values (e.g., `DEBUG=True`)
- Duplicate entries

### ✅ Validate Encrypted File

```bash
himacrypt validate \
  --in .env.enc \
  --private-key ./keys/private.pem
```

### 🛑 Git Pre-commit Hook

```bash
himacrypt git-hook install
```
Prevents committing raw .env files to version control.

🧵 Hybrid Encryption Architecture (RSA + AES)
To ensure both security and performance:

Generate a random AES key

Encrypt .env using AES

Encrypt AES key using RSA public key

Store both encrypted AES key + encrypted .env in .env.enc

Decrypt AES key using RSA private key at runtime

## 🧱 Python API Usage

```python
from himacrypt.core import Encryptor, generate_rsa_keypair, write_keypair_to_dir

# Generate an RSA key pair (returns bytes)
private_pem, public_pem = generate_rsa_keypair(key_size=2048)
write_keypair_to_dir(Path('keys'), private_pem, public_pem)

encryptor = Encryptor()
# Encrypt a file
encryptor.encrypt_env_file(input_path='.env', output_path='.env.enc', public_key_path=Path('keys/public.pem'))

# Decrypt a file
encryptor.decrypt_env_file(input_path='.env.enc', output_path='.env', private_key_path=Path('keys/private.pem'))
```

## 📁 Format Support

| Format | Status |
|--------|---------|
| .env   | ✅ Full support |
| .json  | ✅ Full support |
| .yaml  | ✅ Full support |
| .toml  | ✅ Full support |

## 📌 Roadmap

- [ ] AES-only symmetric fallback mode
- [ ] Secret rotation support
- [ ] AWS/GCP/Vault integrations
- [ ] TUI mode with textual or rich
- [ ] Auto-decrypt wrapper for Python scripts and Docker

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For information about security policies and procedures, please refer to our [Security Policy](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
