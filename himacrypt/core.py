"""Core encryption utilities for himacrypt.

This module implements a minimal Encryptor class providing:
- RSA key generation (PEM)
- AES-GCM encryption of bytes
- RSA-OAEP wrapping/unwrapping of the AES key
- File helpers to encrypt/decrypt simple `.env` files (line-based KEY=VALUE)

This is a focused, tested implementation intended for local development and unit tests.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Optional, Tuple, Union, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)

# optional third-party modules: typed as ModuleType | None for mypy
yaml: Optional[ModuleType]
toml: Optional[ModuleType]
yaml = None
toml = None
try:
    import yaml as _yaml

    yaml = _yaml
except Exception:  # pragma: no cover - optional dependency in tests
    yaml = None
try:
    import toml as _toml

    toml = _toml
except Exception:  # pragma: no cover - optional dependency in tests
    toml = None


def generate_rsa_keypair(
    key_size: int = 4096, private_password: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Generate an RSA keypair and return (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size
    )

    encryption: Union[BestAvailableEncryption, NoEncryption]
    if private_password:
        encryption = BestAvailableEncryption(private_password)
    else:
        encryption = NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


@dataclass
class EncryptedPayload:
    encrypted_key: bytes
    nonce: bytes
    ciphertext: bytes


class Encryptor:
    """Simple Encryptor class for file-based encryption using AES-GCM + RSA keywrap."""

    def __init__(self) -> None:
        pass

    @staticmethod
    def _load_public_key(pem_path: Path) -> RSAPublicKey:
        with pem_path.open("rb") as fh:
            data = fh.read()
        # RSA public key expected
        return cast(RSAPublicKey, serialization.load_pem_public_key(data))

    @staticmethod
    def _load_private_key(
        pem_path: Path, password: Optional[bytes] = None
    ) -> RSAPrivateKey:
        with pem_path.open("rb") as fh:
            data = fh.read()
        # RSA private key expected
        return cast(
            RSAPrivateKey,
            serialization.load_pem_private_key(data, password=password),
        )

    @staticmethod
    def encrypt_bytes(
        plaintext: bytes, public_key: RSAPublicKey
    ) -> EncryptedPayload:
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return EncryptedPayload(
            encrypted_key=encrypted_key, nonce=nonce, ciphertext=ciphertext
        )

    @staticmethod
    def encrypt_data(
        plaintext: bytes, public_key: RSAPublicKey
    ) -> EncryptedPayload:
        """Alias for encrypt_bytes (project roadmap/API consistency)."""
        return Encryptor.encrypt_bytes(plaintext, public_key)

    @staticmethod
    def decrypt_bytes(
        payload: EncryptedPayload,
        private_key: RSAPrivateKey,
        password: Optional[bytes] = None,
    ) -> bytes:
        aes_key = private_key.decrypt(
            payload.encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(payload.nonce, payload.ciphertext, None)

    @staticmethod
    def decrypt_data(
        payload: EncryptedPayload,
        private_key: RSAPrivateKey,
        password: Optional[bytes] = None,
    ) -> bytes:
        """Alias for decrypt_bytes (project roadmap/API consistency)."""
        return Encryptor.decrypt_bytes(payload, private_key, password)

    def encrypt_env_file(
        self,
        input_path: Path,
        output_path: Path,
        public_key_path: Path,
        selected_keys: Optional[set[str]] = None,
    ) -> None:
        """Encrypt a simple KEY=VALUE .env file.

        If `selected_keys` is None, encrypt the whole file as a binary bundle
        (legacy behavior). If `selected_keys` is provided, encrypt only the
        specified keys and write a text `.env` file where encrypted values are
        embedded as `ENC:<base64>` markers.
        """
        public_key = self._load_public_key(public_key_path)

        # If no selected_keys specified, use original full-file binary format
        if not selected_keys:
            plaintext = input_path.read_bytes()
            payload = self.encrypt_bytes(plaintext, public_key)
            with output_path.open("wb") as out:
                out.write(len(payload.encrypted_key).to_bytes(4, "big"))
                out.write(payload.encrypted_key)
                out.write(len(payload.nonce).to_bytes(1, "big"))
                out.write(payload.nonce)
                out.write(payload.ciphertext)
            return

        # Field-level encryption: process as text
        # support .env via existing code path
        text = input_path.read_text(encoding="utf-8")
        out_lines: list[str] = []
        for line in text.splitlines(keepends=False):
            if not line or line.strip().startswith("#") or "=" not in line:
                out_lines.append(line)
                continue
            key, val = line.split("=", 1)
            key_stripped = key.strip()
            if key_stripped in selected_keys:
                # encrypt the value only
                payload = self.encrypt_bytes(val.encode("utf-8"), public_key)
                # serialize payload to bytes same as binary format
                buf = bytearray()
                buf += len(payload.encrypted_key).to_bytes(4, "big")
                buf += payload.encrypted_key
                buf += len(payload.nonce).to_bytes(1, "big")
                buf += payload.nonce
                buf += payload.ciphertext
                b64 = base64.b64encode(bytes(buf)).decode("ascii")
                out_lines.append(f"{key}=ENC:{b64}")
            else:
                out_lines.append(line)

        output_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    def _read_structured(self, input_path: Path, fmt: str) -> Any:
        text = input_path.read_text(encoding="utf-8")
        if fmt == "json":
            return json.loads(text)
        if fmt == "yaml":
            if yaml is None:
                raise RuntimeError("PyYAML not installed")
            return yaml.safe_load(text)
        if fmt == "toml":
            if toml is None:
                raise RuntimeError("toml library not installed")
            return toml.loads(text)
        raise ValueError(f"Unsupported format: {fmt}")

    def _write_structured(
        self, data: Any, output_path: Path, fmt: str
    ) -> None:
        if fmt == "json":
            # deterministic JSON serialization
            output_path.write_text(
                json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            return
        if fmt == "yaml":
            if yaml is None:
                raise RuntimeError("PyYAML not installed")
            # safe_dump has stable sort to minimize diffs
            output_path.write_text(
                yaml.safe_dump(data, sort_keys=True), encoding="utf-8"
            )
            return
        if fmt == "toml":
            if toml is None:
                raise RuntimeError("toml library not installed")
            output_path.write_text(toml.dumps(data), encoding="utf-8")
            return
        raise ValueError(f"Unsupported format: {fmt}")

    def _traverse_and_apply(
        self, obj: Any, selectors: set[str], public_key: Any, encrypt: bool
    ) -> Any:
        """Traverse structured data (dicts/lists) and encrypt/decrypt values
        when the dotted selector path matches selectors. Selectors are simple
        dotted paths like 'a.b.c' matching keys in nested dicts.
        """
        if isinstance(obj, dict):
            new = {}
            for k, v in obj.items():
                # check full key and nested selectors
                if not isinstance(v, (dict, list)):
                    if encrypt:
                        if k in selectors:
                            payload = self.encrypt_bytes(
                                str(v).encode("utf-8"), public_key
                            )
                            buf = bytearray()
                            buf += len(payload.encrypted_key).to_bytes(
                                4, "big"
                            )
                            buf += payload.encrypted_key
                            buf += len(payload.nonce).to_bytes(1, "big")
                            buf += payload.nonce
                            buf += payload.ciphertext
                            new[k] = (
                                f"ENC:{base64.b64encode(bytes(buf)).decode('ascii')}"
                            )
                        else:
                            new[k] = v
                    else:
                        # decrypt any ENC: value when selectors empty (decrypt all)
                        if (
                            isinstance(v, str)
                            and v.startswith("ENC:")
                            and (not selectors or k in selectors)
                        ):
                            b64 = v[len("ENC:") :]
                            raw = base64.b64decode(b64)
                            if len(raw) < 5:
                                raise ValueError("Invalid embedded payload")
                            klen = int.from_bytes(raw[:4], "big")
                            idx = 4
                            enc_key = raw[idx : idx + klen]
                            idx += klen
                            nlen = raw[idx]
                            idx += 1
                            nonce = raw[idx : idx + nlen]
                            idx += nlen
                            ciphertext = raw[idx:]
                            payload = EncryptedPayload(
                                encrypted_key=enc_key,
                                nonce=nonce,
                                ciphertext=ciphertext,
                            )
                            plain = self.decrypt_bytes(
                                payload, public_key, password=None
                            )
                            new[k] = plain.decode("utf-8")
                        else:
                            new[k] = v
                else:
                    # descent into nested structures; also consider dotted selector match
                    nested_selectors = {
                        s.partition(".")[2]
                        for s in selectors
                        if s.startswith(k + ".")
                    }
                    if nested_selectors:
                        new[k] = self._traverse_and_apply(
                            v, nested_selectors, public_key, encrypt
                        )
                    else:
                        new[k] = self._traverse_and_apply(
                            v, selectors, public_key, encrypt
                        )
            return new
        if isinstance(obj, list):
            return [
                self._traverse_and_apply(i, selectors, public_key, encrypt)
                for i in obj
            ]
        # primitives
        return obj

    def encrypt_structured_file(
        self,
        input_path: Path,
        output_path: Path,
        public_key_path: Path,
        fmt: str,
        selected_keys: Optional[set[str]] = None,
    ) -> None:
        public_key = self._load_public_key(public_key_path)
        data = self._read_structured(input_path, fmt)
        if selected_keys:
            data = self._traverse_and_apply(
                data, selected_keys, public_key, encrypt=True
            )
        else:
            # full-file: serialize to bytes and encrypt as binary bundle
            if fmt == "json":
                plaintext = json.dumps(
                    data, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            elif fmt == "yaml":
                if yaml is None:
                    raise RuntimeError("PyYAML not installed")
                plaintext = yaml.safe_dump(data).encode("utf-8")
            elif fmt == "toml":
                if toml is None:
                    raise RuntimeError("toml library not installed")
                plaintext = toml.dumps(data).encode("utf-8")
            else:
                raise ValueError(f"Unsupported format: {fmt}")
            payload = self.encrypt_bytes(plaintext, public_key)
            with output_path.open("wb") as out:
                out.write(len(payload.encrypted_key).to_bytes(4, "big"))
                out.write(payload.encrypted_key)
                out.write(len(payload.nonce).to_bytes(1, "big"))
                out.write(payload.nonce)
                out.write(payload.ciphertext)
            return
        self._write_structured(data, output_path, fmt)

    def decrypt_structured_file(
        self,
        input_path: Path,
        output_path: Path,
        private_key_path: Path,
        fmt: str,
        key_password: Optional[bytes] = None,
    ) -> None:
        private_key = self._load_private_key(
            private_key_path, password=key_password
        )
        # try to read as text structured or binary
        try:
            text = input_path.read_text(encoding="utf-8")
        except Exception:
            text = ""
        # detect ENC markers
        if "ENC:" in text:
            data = self._read_structured(input_path, fmt)
            data = self._traverse_and_apply(
                data, set(), private_key, encrypt=False
            )
            self._write_structured(data, output_path, fmt)
            return
        # fallback: binary full-file
        data = input_path.read_bytes()
        if len(data) < 5:
            raise ValueError("Invalid payload")
        klen = int.from_bytes(data[:4], "big")
        idx = 4
        enc_key = data[idx : idx + klen]
        idx += klen
        nlen = data[idx]
        idx += 1
        nonce = data[idx : idx + nlen]
        idx += nlen
        ciphertext = data[idx:]

        payload = EncryptedPayload(
            encrypted_key=enc_key, nonce=nonce, ciphertext=ciphertext
        )
        plaintext = self.decrypt_bytes(
            payload, private_key, password=key_password
        )
        # write back deterministic
        if fmt == "json":
            # assume plaintext was JSON
            obj = json.loads(plaintext.decode("utf-8"))
            self._write_structured(obj, output_path, fmt)
            return
        if fmt == "yaml":
            if yaml is None:
                raise RuntimeError("PyYAML not installed")
            obj = yaml.safe_load(plaintext.decode("utf-8"))
            self._write_structured(obj, output_path, fmt)
            return
        if fmt == "toml":
            if toml is None:
                raise RuntimeError("toml library not installed")
            obj = toml.loads(plaintext.decode("utf-8"))
            self._write_structured(obj, output_path, fmt)
            return
        raise ValueError(f"Unsupported format: {fmt}")

    def decrypt_env_file(
        self,
        input_path: Path,
        output_path: Path,
        private_key_path: Path,
        key_password: Optional[bytes] = None,
    ) -> None:
        """Decrypt either a full-file binary payload or an env file with
        `ENC:<base64>` markers produced by field-level encryption.
        """
        private_key = self._load_private_key(
            private_key_path, password=key_password
        )

        # Try to read as text and detect ENC markers
        text = input_path.read_text(encoding="utf-8", errors="ignore")
        if "ENC:" in text:
            out_lines: list[str] = []
            for line in text.splitlines(keepends=False):
                if not line or line.strip().startswith("#") or "=" not in line:
                    out_lines.append(line)
                    continue
                key, val = line.split("=", 1)
                if val.startswith("ENC:"):
                    b64 = val[len("ENC:") :]
                    raw = base64.b64decode(b64)
                    # parse raw payload
                    if len(raw) < 5:
                        raise ValueError("Invalid embedded payload")
                    klen = int.from_bytes(raw[:4], "big")
                    idx = 4
                    enc_key = raw[idx : idx + klen]
                    idx += klen
                    nlen = raw[idx]
                    idx += 1
                    nonce = raw[idx : idx + nlen]
                    idx += nlen
                    ciphertext = raw[idx:]
                    payload = EncryptedPayload(
                        encrypted_key=enc_key,
                        nonce=nonce,
                        ciphertext=ciphertext,
                    )
                    plaintext = self.decrypt_bytes(
                        payload, private_key, password=key_password
                    )
                    out_lines.append(f"{key}={plaintext.decode('utf-8')}")
                else:
                    out_lines.append(line)

            output_path.write_text(
                "\n".join(out_lines) + "\n", encoding="utf-8"
            )
            return

        # Fallback: full-file binary format
        data = input_path.read_bytes()

        if len(data) < 5:
            raise ValueError("Invalid payload")
        klen = int.from_bytes(data[:4], "big")
        idx = 4
        enc_key = data[idx : idx + klen]
        idx += klen
        nlen = data[idx]
        idx += 1
        nonce = data[idx : idx + nlen]
        idx += nlen
        ciphertext = data[idx:]

        payload = EncryptedPayload(
            encrypted_key=enc_key, nonce=nonce, ciphertext=ciphertext
        )
        plaintext = self.decrypt_bytes(
            payload, private_key, password=key_password
        )

        output_path.write_bytes(plaintext)


def write_keypair_to_dir(
    output_dir: Path,
    private_pem: bytes,
    public_pem: bytes,
    private_name: str = "private.pem",
    public_name: str = "public.pem",
) -> None:
    """Helper to write PEM files to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / private_name).write_bytes(private_pem)
    (output_dir / public_name).write_bytes(public_pem)


__all__ = ["Encryptor", "generate_rsa_keypair", "write_keypair_to_dir"]


def rotate_keys(
    directory: Path,
    pattern: str,
    old_private_path: Path,
    new_public_path: Path,
    backup: bool = True,
) -> int:
    """Rotate encrypted files in a directory from old key to new key.

    Returns the number of files rotated.
    """
    encryptor = Encryptor()
    count = 0
    # derive suffix if pattern is like "*.ext" otherwise fallback to pattern
    suffix = pattern[1:] if pattern.startswith("*") else pattern
    for src in directory.iterdir():
        if not src.is_file():
            continue
        if not src.name.endswith(suffix):
            continue
        tmp = src.with_suffix(src.suffix + ".dec")
        # decrypt using old private
        encryptor.decrypt_env_file(src, tmp, old_private_path)
        # backup original
        if backup:
            bak = src.with_suffix(src.suffix + ".bak")
            src.replace(bak)
        else:
            src.unlink()
        # re-encrypt with new public
        encryptor.encrypt_env_file(tmp, src, new_public_path)
        tmp.unlink()
        count += 1
    return count
