"""Module for handling validation command arguments in himacrypt CLI."""

import argparse
from pathlib import Path
from typing import Optional, Set


class ValidateArguments:
    """Class for handling and validating environment file validation arguments."""

    # Common environment variables that shouldn't contain certain values
    SENSITIVE_VARS = {
        "PASSWORD",
        "SECRET",
        "KEY",
        "TOKEN",
        "CREDENTIAL",
        "AUTH",
    }

    # Values that might indicate development/test settings
    INSECURE_VALUES = {
        "true",
        "True",
        "TRUE",
        "1",
        "yes",
        "development",
        "dev",
        "test",
        "testing",
    }

    def __init__(self) -> None:
        """Initialize ValidateArguments."""
        self.input_file: Optional[Path] = None
        self.ignore_warnings: bool = False
        self.check_naming: bool = True
        self.check_values: bool = True
        self.check_duplicates: bool = True
        self.excluded_vars: Set[str] = set()
        self.required_vars: Set[str] = set()
        self.config_file: Optional[Path] = None
        self.output_format: str = "text"

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """Add validation-related arguments to the argument parser.

        Args:
            parser: The argparse parser to add arguments to.
        """
        parser.add_argument(
            "-i",
            "--in",
            dest="input_file",
            type=Path,
            required=True,
            help="Path to the environment file to validate",
        )
        parser.add_argument(
            "--ignore-warnings",
            action="store_true",
            help="Only show errors, ignore warnings",
        )
        parser.add_argument(
            "--no-check-naming",
            action="store_false",
            dest="check_naming",
            help="Skip variable naming convention checks",
        )
        parser.add_argument(
            "--no-check-values",
            action="store_false",
            dest="check_values",
            help="Skip value validation checks",
        )
        parser.add_argument(
            "--no-check-duplicates",
            action="store_false",
            dest="check_duplicates",
            help="Skip duplicate variable checks",
        )
        parser.add_argument(
            "--exclude",
            type=str,
            help="Comma-separated list of variables to exclude from validation",
        )
        parser.add_argument(
            "--require",
            type=str,
            help="Comma-separated list of required variables",
        )
        parser.add_argument(
            "--config",
            type=Path,
            help="Path to validation configuration file (YAML/JSON)",
        )
        parser.add_argument(
            "--format",
            choices=["text", "json", "yaml"],
            default="text",
            help="Output format for validation results",
        )

    def process_arguments(self, args: argparse.Namespace) -> None:
        """Process and validate the parsed arguments.

        Args:
            args: The parsed command line arguments.

        Raises:
            ValueError: If input file doesn't exist or if config file is specified but doesn't exist.
        """
        self.input_file = args.input_file
        self.ignore_warnings = args.ignore_warnings
        self.check_naming = args.check_naming
        self.check_values = args.check_values
        self.check_duplicates = args.check_duplicates
        self.output_format = args.format

        # Process excluded variables
        if args.exclude:
            self.excluded_vars = {v.strip() for v in args.exclude.split(",")}

        # Process required variables
        if args.require:
            self.required_vars = {v.strip() for v in args.require.split(",")}

        # Process config file
        if args.config:
            self.config_file = args.config
            if not self.config_file.exists():
                raise ValueError(f"Config file not found: {self.config_file}")

        # Validate input file exists
        if not self.input_file.exists():
            raise ValueError(f"Input file not found: {self.input_file}")

    def get_validation_rules(self) -> dict[str, object]:
        """Get the validation rules for environment variables.

        Returns:
            dict[str, object]: Dictionary containing validation rules.
                - sensitive_vars: Set[str] - Variables that should be treated as sensitive
                - insecure_values: Set[str] - Values that might indicate security issues
                - required_vars: Set[str] - Variables that must be present
                - excluded_vars: Set[str] - Variables to exclude from validation
                - checks: dict[str, bool] - Enabled validation checks
        """
        return {
            "sensitive_vars": self.SENSITIVE_VARS,
            "insecure_values": self.INSECURE_VALUES,
            "required_vars": self.required_vars,
            "excluded_vars": self.excluded_vars,
            "checks": {
                "naming": self.check_naming,
                "values": self.check_values,
                "duplicates": self.check_duplicates,
            },
        }
