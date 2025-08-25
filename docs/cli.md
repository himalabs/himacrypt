# CLI Reference

This document provides a reference for each CLI subcommand, flags, expected behavior, and examples.

Note: The CLI wiring is defined in `himacrypt/cli/main.py`. The commands here reflect the implemented argument handlers. Some commands may contain TODOs in implementation — this reference documents the arguments and expected behavior.

## Common conventions

- Long options use `--long-name` and short options use `-s` when defined.
- File paths accept absolute or relative paths. Use quotes when paths contain spaces.
- Exit codes: `0` success, `1` general error. Specific CLI may return other exit codes on type errors or validation failures.

## Commands

### keygen — Generate RSA key pair

Usage:

```bash
himacrypt keygen --out <dir> [--key-size <bits>] [--private-key-password <pwd>] [--public-key-name <name>] [--private-key-name <name>] [--force]
```

Options:
- `--out`, `-o` (required): Directory where keys will be written.
- `--key-size`, `-s`: RSA key size (choices: 2048, 3072, 4096). Default: 4096.
- `--private-key-password`, `-p`: Optional password to protect the private key.
- `--public-key-name`: Filename for public key (default `public.pem`).
- `--private-key-name`: Filename for private key (default `private.pem`).
- `--force`, `-f`: Overwrite existing files if present.

Behavior:
- Creates the output directory if missing.
- Validates that files do not exist unless `--force` is provided.

Example:

```bash
himacrypt keygen --out ./keys --key-size 4096
```

Notes:

- The CLI supports using a KeyProvider abstraction to locate or provision keys. By default the `keygen` command writes `private.pem` and `public.pem` into the specified directory.
- To integrate with custom key stores (AWS KMS, GCP KMS), implement a KeyProvider and adapt the CLI wiring to call into that provider. See `docs/key_provider.md` for details.

### encrypt — Encrypt a file

Usage:

```bash
himacrypt encrypt --in <input> --out <output> --public-key <pub.pem> [--keys key1,key2] [--format env|json|yaml|toml] [--backup]
```

Options:
- `--in`, `-i` (required): Input file path to encrypt.
- `--out`, `-o` (required): Output file path for encrypted payload.
- `--public-key`, `-k` (required): Path to RSA public key for encryption.
- `--keys`: Comma-separated list of keys to encrypt (field-level encryption).
- `--format`: Input/output format. Default `env`.
- `--backup`: Create a backup before overwriting an existing output file.

Behavior:
- Reads the input file, encrypts either the entire file or selected keys, writes the encrypted artifact.

Example:

```bash
himacrypt encrypt --in .env --out .env.enc --public-key ./keys/public.pem
```

Notes on `--format` and selectors:

- The `--format` flag accepts `env`, `json`, `yaml`, or `toml`. When using structured formats (`json`, `yaml`, `toml`) you may pass dotted selectors to `--keys` to encrypt nested fields. Example:

```bash
himacrypt encrypt --in config.json --out config.json.enc --public-key ./keys/public.pem --format json --keys "database.password,api.token"
```

This will replace selected fields with `ENC:<base64>` markers in the resulting file while leaving other fields intact.

### decrypt — Decrypt a file

Usage:

```bash
himacrypt decrypt --in <input> --out <output> --private-key <priv.pem> [--key-password <pwd>] [--backup]
```

Options:
- `--in`, `-i` (required): Encrypted file path.
- `--out`, `-o` (required): Path to write decrypted output.
- `--private-key`, `-k` (required): RSA private key path.
- `--key-password`, `-p`: Password to unlock private key if encrypted.
- `--backup`: Create a backup of existing output file.

Behavior:
- Decrypts the AES key with RSA private key, then uses AES to decrypt content and write output.

Example:

```bash
himacrypt decrypt --in .env.enc --out .env --private-key ./keys/private.pem
```

### lint — Lint environment files

Usage:

```bash
himacrypt lint --in <file> [--ignore-warnings] [--format text|json|yaml] [--config <config>]
```

Options:
- `--in`, `-i` (required): Path to the file to lint.
- `--ignore-warnings`: Only report errors.
- `--format`: Output format for lint results.
- `--config`: Optional linting config path.

Behavior:
- Checks for missing keys, unsafe values (e.g., `DEBUG=True`), duplicate entries, and naming conventions.

Example:

```bash
himacrypt lint --in .env
```

### validate — Validate files and encrypted payloads

Usage:

```bash
himacrypt validate --in <file> [--require key1,key2] [--exclude key1] [--format text|json|yaml] [--config <config>]
```

Options:
- `--in`, `-i` (required): File to validate (plaintext or encrypted payload).
- `--require`: Comma-separated list of required keys.
- `--exclude`: Variables to exclude from validation.
- `--format`: Output format.
- `--config`: Validation configuration file.

Behavior:
- Ensures required keys exist, that secure defaults are used, and reports insecure values or missing items.

---

For more examples and recommended workflows, consult `docs/usage.md`.
