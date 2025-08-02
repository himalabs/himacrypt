"""Module for handling linting command arguments in himacrypt CLI."""

import argparse
from pathlib import Path
from typing import Optional


class LintArguments:
    """Class for handling and validating linting command arguments."""

    def __init__(self) -> None:
        """Initialize LintArguments."""
        self.input_file: Optional[Path] = None
        self.ignore_warnings: bool = False
        self.output_format: str = "text"
        self.config_file: Optional[Path] = None

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """Add linting-related arguments to the argument parser.

        Args:
            parser: The argparse parser to add arguments to.
        """
        parser.add_argument(
            "-i",
            "--in",
            dest="input_file",
            type=Path,
            required=True,
            help="Path to the environment file to lint",
        )
        parser.add_argument(
            "--ignore-warnings",
            action="store_true",
            help="Ignore warning-level issues",
        )
        parser.add_argument(
            "--format",
            choices=["text", "json", "yaml"],
            default="text",
            help="Output format for the linting results",
        )
        parser.add_argument(
            "--config",
            type=Path,
            help="Path to custom linting configuration file",
        )

    def process_arguments(self, args: argparse.Namespace) -> None:
        """Process and validate the parsed arguments.

        Args:
            args: The parsed command line arguments.

        Raises:
            ValueError: If the input file doesn't exist or if config file is specified but doesn't exist.
        """
        self.input_file = args.input_file
        self.ignore_warnings = args.ignore_warnings
        self.output_format = args.format
        self.config_file = args.config

        # Validate input file exists
        if not self.input_file.exists():
            raise ValueError(f"Input file not found: {self.input_file}")

        # Validate config file if specified
        if self.config_file and not self.config_file.exists():
            raise ValueError(f"Config file not found: {self.config_file}")
