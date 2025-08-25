"""Core encryption utilities for himacrypt.

This module implements a minimal Encryptor class providing:
- RSA key generation (PEM)
- AES-GCM encryption of bytes
- RSA-OAEP wrapping/unwrapping of the AES key
- File helpers to encrypt/decrypt simple `.env` files (line-based KEY=VALUE)

This is a focused, tested implementation intended for local development and unit tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union, cast

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
        self, input_path: Path, output_path: Path, public_key_path: Path
    ) -> None:
        """Encrypt a simple KEY=VALUE .env file and write a binary payload."""
        public_key = self._load_public_key(public_key_path)
        plaintext = input_path.read_bytes()

        payload = self.encrypt_bytes(plaintext, public_key)

        with output_path.open("wb") as out:
            out.write(len(payload.encrypted_key).to_bytes(4, "big"))
            out.write(payload.encrypted_key)
            out.write(len(payload.nonce).to_bytes(1, "big"))
            out.write(payload.nonce)
            out.write(payload.ciphertext)

    def decrypt_env_file(
        self,
        input_path: Path,
        output_path: Path,
        private_key_path: Path,
        key_password: Optional[bytes] = None,
    ) -> None:
        """Decrypt a binary payload produced by encrypt_env_file."""
        private_key = self._load_private_key(
            private_key_path, password=key_password
        )
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
