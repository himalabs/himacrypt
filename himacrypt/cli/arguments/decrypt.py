"""Module for handling decryption command arguments in himacrypt CLI."""

import argparse
from pathlib import Path
from typing import Optional


class DecryptArguments:
    """Class for handling and validating decryption command arguments."""

    def __init__(self) -> None:
        """Initialize DecryptArguments."""
        self.input_file: Optional[Path] = None
        self.output_file: Optional[Path] = None
        self.private_key: Optional[Path] = None
        self.key_password: Optional[str] = None
        self.backup: bool = False

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """Add decryption-related arguments to the argument parser.

        Args:
            parser: The argparse parser to add arguments to.
        """
        parser.add_argument(
            "-i",
            "--in",
            dest="input_file",
            type=Path,
            required=True,
            help="Path to the encrypted file to decrypt",
        )
        parser.add_argument(
            "-o",
            "--out",
            dest="output_file",
            type=Path,
            required=True,
            help="Path to save the decrypted file",
        )
        parser.add_argument(
            "-k",
            "--private-key",
            dest="private_key",
            type=Path,
            required=True,
            help="Path to the RSA private key file",
        )
        parser.add_argument(
            "-p",
            "--key-password",
            dest="key_password",
            help="Password for encrypted private key (if needed)",
        )
        parser.add_argument(
            "--backup",
            action="store_true",
            help="Create a backup of the output file if it exists",
        )

    def process_arguments(self, args: argparse.Namespace) -> None:
        """Process and validate the parsed arguments.

        Args:
            args: The parsed command line arguments.

        Raises:
            ValueError: If required files don't exist or if output would overwrite without backup.
        """
        self.input_file = args.input_file
        self.output_file = args.output_file
        self.private_key = args.private_key
        self.key_password = args.key_password
        self.backup = args.backup

        # Validate input file exists
        if not self.input_file.exists():
            raise ValueError(f"Input file not found: {self.input_file}")

        # Validate private key exists
        if not self.private_key.exists():
            raise ValueError(f"Private key file not found: {self.private_key}")

        # Check if output file exists and backup not requested
        if self.output_file.exists() and not self.backup:
            raise ValueError(
                f"Output file {self.output_file} exists. Use --backup to overwrite."
            )
