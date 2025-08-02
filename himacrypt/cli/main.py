"""Main entry point for himacrypt CLI."""

import argparse
import sys

from .arguments import (
    DecryptArguments,
    EncryptArguments,
    KeygenArguments,
    LintArguments,
)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.

    Returns:
        argparse.ArgumentParser: The configured parser
    """
    parser = argparse.ArgumentParser(
        description="Securely encrypt and manage environment variables"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Keygen command
    keygen_parser = subparsers.add_parser(
        "keygen", help="Generate RSA key pair for encryption"
    )
    KeygenArguments.add_arguments(keygen_parser)

    # Encrypt command
    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt environment file"
    )
    EncryptArguments.add_arguments(encrypt_parser)

    # Decrypt command
    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt environment file"
    )
    DecryptArguments.add_arguments(decrypt_parser)

    # Lint command
    lint_parser = subparsers.add_parser("lint", help="Lint environment file")
    LintArguments.add_arguments(lint_parser)

    return parser


def main() -> int:
    """Main entry point for the CLI.

    Returns:
        int: Exit code (0 for success, non-zero for error)
    """
    parser = create_parser()
    args = parser.parse_args()

    try:
        if args.command == "keygen":
            keygen_args = KeygenArguments()
            keygen_args.process_arguments(args)
            # TODO: Implement key generation logic
        elif args.command == "encrypt":
            encrypt_args = EncryptArguments()
            encrypt_args.process_arguments(args)
            # TODO: Implement encryption logic
        elif args.command == "decrypt":
            decrypt_args = DecryptArguments()
            decrypt_args.process_arguments(args)
            # TODO: Implement decryption logic
        elif args.command == "lint":
            lint_args = LintArguments()
            lint_args.process_arguments(args)
            # TODO: Implement linting logic
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
