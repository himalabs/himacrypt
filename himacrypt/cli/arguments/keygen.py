"""Module for handling key generation command arguments in himacrypt CLI."""

import argparse
from pathlib import Path
from typing import Optional


class KeygenArguments:
    """Class for handling and validating key generation command arguments."""

    DEFAULT_KEY_SIZE = 4096
    SUPPORTED_KEY_SIZES = [2048, 3072, 4096]
    DEFAULT_PUBLIC_KEY_NAME = "public.pem"
    DEFAULT_PRIVATE_KEY_NAME = "private.pem"

    def __init__(self) -> None:
        """Initialize KeygenArguments."""
        self.output_dir: Optional[Path] = None
        self.key_size: int = self.DEFAULT_KEY_SIZE
        self.private_key_password: Optional[str] = None
        self.public_key_name: str = self.DEFAULT_PUBLIC_KEY_NAME
        self.private_key_name: str = self.DEFAULT_PRIVATE_KEY_NAME
        self.force: bool = False

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """Add key generation related arguments to the argument parser.

        Args:
            parser: The argparse parser to add arguments to.
        """
        parser.add_argument(
            "-o",
            "--out",
            dest="output_dir",
            type=Path,
            required=True,
            help="Directory to save the generated key pair",
        )
        parser.add_argument(
            "-s",
            "--key-size",
            type=int,
            choices=KeygenArguments.SUPPORTED_KEY_SIZES,
            default=KeygenArguments.DEFAULT_KEY_SIZE,
            help=f"RSA key size in bits (default: {KeygenArguments.DEFAULT_KEY_SIZE})",
        )
        parser.add_argument(
            "-p",
            "--private-key-password",
            dest="private_key_password",
            help="Password to encrypt the private key (optional)",
        )
        parser.add_argument(
            "--public-key-name",
            dest="public_key_name",
            default=KeygenArguments.DEFAULT_PUBLIC_KEY_NAME,
            help=f"Name for the public key file (default: {KeygenArguments.DEFAULT_PUBLIC_KEY_NAME})",
        )
        parser.add_argument(
            "--private-key-name",
            dest="private_key_name",
            default=KeygenArguments.DEFAULT_PRIVATE_KEY_NAME,
            help=f"Name for the private key file (default: {KeygenArguments.DEFAULT_PRIVATE_KEY_NAME})",
        )
        parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Overwrite existing key files if they exist",
        )

    def process_arguments(self, args: argparse.Namespace) -> None:
        """Process and validate the parsed arguments.

        Args:
            args: The parsed command line arguments.

        Raises:
            ValueError: If output directory is invalid or if key files exist and force is not set.
        """
        self.output_dir = args.output_dir
        self.key_size = args.key_size
        self.private_key_password = args.private_key_password
        self.public_key_name = args.public_key_name
        self.private_key_name = args.private_key_name
        self.force = args.force

        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Check if key files already exist
        public_key_path = self.output_dir / self.public_key_name
        private_key_path = self.output_dir / self.private_key_name

        if not self.force:
            if public_key_path.exists():
                raise ValueError(
                    f"Public key file already exists: {public_key_path}. Use --force to overwrite."
                )
            if private_key_path.exists():
                raise ValueError(
                    f"Private key file already exists: {private_key_path}. Use --force to overwrite."
                )

    @property
    def public_key_path(self) -> Path:
        """Get the full path for the public key file.

        Returns:
            Path: The absolute path where the public key will be saved.

        Raises:
            ValueError: If output_dir is not set.
        """
        if self.output_dir is None:
            raise ValueError("Output directory is not set")
        return self.output_dir / self.public_key_name

    @property
    def private_key_path(self) -> Path:
        """Get the full path for the private key file.

        Returns:
            Path: The absolute path where the private key will be saved.

        Raises:
            ValueError: If output_dir is not set.
        """
        if self.output_dir is None:
            raise ValueError("Output directory is not set")
        return self.output_dir / self.private_key_name
