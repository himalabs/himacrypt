# KeyProvider

The `KeyProvider` abstraction defines how applications obtain encryption keys. This allows the library to support multiple backends (local files, AWS KMS, GCP KMS, HashiCorp Vault, etc.) while keeping the `Encryptor` code generic.

Interfaces
- `KeyProvider` (abstract):
  - `get_public_key_path() -> Path` — path to the public key PEM
  - `get_private_key_path() -> Path` — path to the private key PEM
  - `provision_keys(out_dir: Path, key_size: int = 4096, password: Optional[bytes] = None) -> Tuple[Path, Path]` — create keys and return (private_path, public_path)

File-backed provider

`FileKeyProvider` is a simple implementation that reads/writes `private.pem` and `public.pem` under a directory. It also supports provisioning new RSA keypairs using the `generate_rsa_keypair` helper in `himacrypt.core`.

Usage example

```python
from pathlib import Path
from himacrypt.key_provider import FileKeyProvider

provider = FileKeyProvider(Path('keys'))
priv, pub = provider.provision_keys(out_dir=Path('keys'), key_size=2048)
print('private:', priv)
print('public: ', pub)
```

Extending

To add an external KMS provider, implement the `KeyProvider` interface and register/use it from your application or CLI layer.
