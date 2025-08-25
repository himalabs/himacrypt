# API Reference

This section documents the public Python API that himacrypt exposes for programmatic usage. The implementation may evolve; this reference focuses on high-level classes and functions you are likely to use.

> Note: File and symbol names reflect a recommended layout. If your local project has the code in slightly different modules (for example `himacrypt.core` vs `himacrypt_cli.core`), adapt the import paths accordingly.

## High-level usage

### Encryptor

A convenience class that bundles encryption and decryption helpers for common file formats.

Example:

```python
from himacrypt.core import Encryptor

encryptor = Encryptor()

# Encrypt a file
encryptor.encrypt_env_file(input_path='.env', output_path='.env.enc', public_key_path='keys/public.pem')

# Decrypt a file
plaintext = encryptor.decrypt_env_file(input_path='.env.enc', output_path='.env', private_key_path='keys/private.pem')
```

Possible methods (recommended minimal API):

- `Encryptor.encrypt_env_file(input_path: str | Path, output_path: str | Path, public_key_path: str | Path, keys: Optional[list[str]] = None, format: str = "env") -> None`
- `Encryptor.decrypt_env_file(input_path: str | Path, output_path: str | Path, private_key_path: str | Path, key_password: Optional[str] = None) -> str`
 - `Encryptor.encrypt_structured_file(input_path: str | Path, output_path: str | Path, public_key_path: str | Path, fmt: str, selected_keys: Optional[set[str]] = None) -> None`
 - `Encryptor.decrypt_structured_file(input_path: str | Path, output_path: str | Path, private_key_path: str | Path, fmt: str, key_password: Optional[str] = None) -> None`
- `Encryptor.encrypt_data(data: bytes, public_key: rsa.PublicKey) -> bytes`
- `Encryptor.decrypt_data(encrypted: bytes, private_key: rsa.PrivateKey, key_password: Optional[str]=None) -> bytes`

### Exceptions

The library should raise clear exceptions for problems:

- `FileNotFoundError` for missing files
- `ValueError` for invalid formats or arguments
- `CryptoError` (or `cryptography`-specific exceptions) for cryptographic failures

### Types

- `Path` and `str` are accepted interchangeably for file path arguments.
- Functions should return `None` for operations that write to disk; decryption helpers may return plaintext bytes or string.

## Extending the API

- Add support for remote key management systems (AWS KMS, GCP KMS) by implementing a KeyProvider interface.
- Expose lower-level primitives (encrypt/decrypt bytes) for embedding in other systems.

---

For actual function signatures, consult the code in `himacrypt/core.py` or the module where encryption logic is implemented.

See also: `docs/key_provider.md` for the `KeyProvider` interface and file-backed provider.
