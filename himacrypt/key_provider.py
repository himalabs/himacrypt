from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Tuple

from .core import generate_rsa_keypair, write_keypair_to_dir


class KeyProvider(ABC):
    """Abstract interface for obtaining keys used by Encryptor.

    Implementations may fetch keys from files, environment, or external KMS.
    """

    @abstractmethod
    def get_public_key_path(self) -> Path:
        raise NotImplementedError

    @abstractmethod
    def get_private_key_path(self) -> Path:
        raise NotImplementedError

    @abstractmethod
    def provision_keys(
        self,
        *,
        out_dir: Path,
        key_size: int = 4096,
        password: Optional[bytes] = None,
    ) -> Tuple[Path, Path]:
        """Provision keys and return (private_path, public_path)."""
        raise NotImplementedError


class FileKeyProvider(KeyProvider):
    """Simple file-backed key provider.

    It expects to find `private.pem` and `public.pem` under a directory, or can generate them.
    """

    def __init__(
        self,
        directory: Path,
        private_name: str = "private.pem",
        public_name: str = "public.pem",
    ) -> None:
        self.directory = directory
        self.private_name = private_name
        self.public_name = public_name

    def get_public_key_path(self) -> Path:
        return self.directory / self.public_name

    def get_private_key_path(self) -> Path:
        return self.directory / self.private_name

    def provision_keys(
        self,
        *,
        out_dir: Path,
        key_size: int = 4096,
        password: Optional[bytes] = None,
    ) -> Tuple[Path, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        priv, pub = generate_rsa_keypair(
            key_size=key_size, private_password=password
        )
        write_keypair_to_dir(
            out_dir,
            priv,
            pub,
            private_name=self.private_name,
            public_name=self.public_name,
        )
        return out_dir / self.private_name, out_dir / self.public_name


__all__ = ["KeyProvider", "FileKeyProvider"]
