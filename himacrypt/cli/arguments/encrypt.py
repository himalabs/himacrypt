"""Module for handling encryption command arguments in himacrypt CLI."""

import argparse
from pathlib import Path
from typing import Optional, Set


class EncryptArguments:
    """Class for handling and validating encryption command arguments."""

    def __init__(self) -> None:
        """Initialize EncryptArguments."""
        self.input_file: Optional[Path] = None
        self.output_file: Optional[Path] = None
        self.public_key: Optional[Path] = None
        self.selected_keys: Set[str] = set()
        self.format: str = "env"
        self.backup: bool = False

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """Add encryption-related arguments to the argument parser.

        Args:
            parser: The argparse parser to add arguments to.
        """
        parser.add_argument(
            "-i",
            "--in",
            dest="input_file",
            type=Path,
            required=True,
            help="Path to the file to encrypt",
        )
        parser.add_argument(
            "-o",
            "--out",
            dest="output_file",
            type=Path,
            required=True,
            help="Path to save the encrypted file",
        )
        parser.add_argument(
            "-k",
            "--public-key",
            dest="public_key",
            type=Path,
            required=True,
            help="Path to the RSA public key file",
        )
        parser.add_argument(
            "--keys",
            type=str,
            help="Comma-separated list of specific keys to encrypt (default: all)",
        )
        parser.add_argument(
            "--format",
            choices=["env", "json", "yaml", "toml"],
            default="env",
            help="Format of the input/output files",
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
        self.public_key = args.public_key
        self.format = args.format
        self.backup = args.backup

        # Process selected keys if specified
        if args.keys:
            self.selected_keys = {k.strip() for k in args.keys.split(",")}

        # Validate input file exists
        if not self.input_file.exists():
            raise ValueError(f"Input file not found: {self.input_file}")

        # Validate public key exists
        if not self.public_key.exists():
            raise ValueError(f"Public key file not found: {self.public_key}")

        # Check if output file exists and backup not requested
        if self.output_file.exists() and not self.backup:
            raise ValueError(
                f"Output file {self.output_file} exists. Use --backup to overwrite."
            )
