"""Main entry point for himacrypt CLI."""

import argparse
import sys

from himacrypt.core import rotate_keys

from .arguments import (
    DecryptArguments,
    EncryptArguments,
    KeygenArguments,
    LintArguments,
    RotateArguments,
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

    # Rotate command
    rotate_parser = subparsers.add_parser(
        "rotate", help="Rotate encrypted files to a new key"
    )
    RotateArguments.add_arguments(rotate_parser)

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
            return 0
        elif args.command == "encrypt":
            encrypt_args = EncryptArguments()
            encrypt_args.process_arguments(args)
            # TODO: Implement encryption logic
            return 0
        elif args.command == "decrypt":
            decrypt_args = DecryptArguments()
            decrypt_args.process_arguments(args)
            # TODO: Implement decryption logic
            return 0
        elif args.command == "lint":
            lint_args = LintArguments()
            lint_args.process_arguments(args)
            # TODO: Implement linting logic
            return 0
        elif args.command == "rotate":
            rotate_args = RotateArguments()
            rotate_args.process_arguments(args)
            # Validate required rotate args and narrow types for static checkers
            old_private = rotate_args.old_private
            new_public = rotate_args.new_public
            if old_private is None or new_public is None:
                print(
                    "Error: --old-private and --new-public are required for rotate",
                    file=sys.stderr,
                )
                return 2

            # call core.rotate_keys and report
            n = rotate_keys(
                rotate_args.in_dir,
                rotate_args.pattern,
                old_private,
                new_public,
                backup=rotate_args.backup,
            )
            print(f"Rotated {n} file(s)")
            return 0
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
