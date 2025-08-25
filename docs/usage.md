# Usage and Quick Start

This page explains the core concepts of himacrypt and provides practical CLI and Python API examples to get you started quickly.

## Core concepts

- Hybrid encryption: himacrypt uses symmetric encryption (AES) for the actual file contents and asymmetric encryption (RSA) to protect the AES key. This provides both performance and secure key distribution.
- File formats: himacrypt supports `.env`, `.json`, `.yaml`/`.yml`, and `.toml` files.
- Field-level encryption: You may encrypt only a subset of keys inside a file instead of an entire file (where supported by implementation).
- Key management: Public and private RSA key pair are used. Keep the private key secret and protect it with filesystem permissions or a password.

## Quick CLI examples

### 1) Generate an RSA key pair

```bash
poetry run himacrypt keygen --out ./keys --key-size 4096
```

This should produce:
- `./keys/public.pem` — distribute (or store) this to encrypt files
- `./keys/private.pem` — keep secret; use to decrypt

### 2) Encrypt a file

Encrypt a `.env` file using a public key:

```bash
poetry run himacrypt encrypt --in .env --out .env.enc --public-key ./keys/public.pem
```

Options:
- `--keys` — comma-separated list of specific keys to encrypt (field-level encryption).
- `--format` — file format (`env`, `json`, `yaml`, `toml`).

### 3) Decrypt a file

```bash
poetry run himacrypt decrypt --in .env.enc --out .env --private-key ./keys/private.pem
```

If your private key is password protected, pass the `--key-password` flag (or use a secure prompt implemented in CLI logic).

### 4) Lint / Validate

Lint a file for common issues:

```bash
poetry run himacrypt lint --in .env
```

Validate file integrity or encrypted payloads:

```bash
poetry run himacrypt validate --in .env.enc --format json
```

## Python API examples

Import and call the library functions (high-level example):

```python
from himacrypt.core import Encryptor

encryptor = Encryptor()

# Encrypt a file
encryptor.encrypt_env_file(input_path='.env', output_path='.env.enc', public_key_path='keys/public.pem')

# Decrypt a file
decryptor = Encryptor()
plain_data = decryptor.decrypt_env_file(input_path='.env.enc', output_path='.env', private_key_path='keys/private.pem')
```

### Error handling

The Python API raises exceptions for file-not-found, invalid format, and cryptographic failures. Catch these and fail gracefully (log and exit non-zero for CLI wrappers).

## Recommended workflows

- Development: keep a `.env.example` or `.env.template` in repo that lists keys without secrets.
- CI / Deployment: store the private key in a secure secrets manager and mount at runtime; never store private keys in the repository.
- Rotation: periodically rotate RSA key pairs and re-encrypt files. Consider including rotation helpers in automation.

## Example: CI runtime decrypt step

In CI or container entrypoints, mount the private key and decrypt on startup (avoid writing decrypted content to logs):

```bash
# mount private key into container at /run/secrets/private.pem
himacrypt decrypt --in /app/.env.enc --out /app/.env --private-key /run/secrets/private.pem
```

## Troubleshooting

- If encryption fails, confirm the public key exists and is valid PEM format.
- If decryption fails, ensure private key matches the public key used for encryption and that password (if used) is correct.
- Use `himacrypt validate` to check encrypted payload integrity if implemented.

---

This page focuses on practical commands. For a full reference of flags and options see the CLI Reference: `docs/cli.md`. For programmatic integration, see `docs/api.md`.
