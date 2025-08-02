"""Tests for CLI argument handling."""

import argparse

import pytest

from himacrypt.cli.arguments import (
    KeygenArguments,
)


class TestKeygenArguments:
    """Test cases for key generation arguments."""

    def test_default_values(self):
        """Test default values are set correctly."""
        args = KeygenArguments()
        assert args.key_size == 4096
        assert args.public_key_name == "public.pem"
        assert args.private_key_name == "private.pem"
        assert not args.force
        assert args.private_key_password is None
        assert args.output_dir is None

    def test_valid_arguments(self, tmp_path):
        """Test processing of valid arguments."""
        parser = argparse.ArgumentParser()
        KeygenArguments.add_arguments(parser)

        # Test with minimal required arguments
        args = parser.parse_args(["--out", str(tmp_path)])
        keygen_args = KeygenArguments()
        keygen_args.process_arguments(args)
        assert keygen_args.output_dir == tmp_path
        assert keygen_args.key_size == 4096  # default value

        # Test with all arguments
        output_dir = tmp_path / "keys"
        args = parser.parse_args(
            [
                "--out",
                str(output_dir),
                "--key-size",
                "2048",
                "--private-key-password",
                "secret",
                "--public-key-name",
                "custom_public.pem",
                "--private-key-name",
                "custom_private.pem",
                "--force",
            ]
        )
        keygen_args = KeygenArguments()
        keygen_args.process_arguments(args)

        assert keygen_args.output_dir == output_dir
        assert keygen_args.key_size == 2048
        assert keygen_args.private_key_password == "secret"
        assert keygen_args.public_key_name == "custom_public.pem"
        assert keygen_args.private_key_name == "custom_private.pem"
        assert keygen_args.force

    def test_invalid_key_size(self):
        """Test that invalid key sizes are rejected."""
        parser = argparse.ArgumentParser()
        KeygenArguments.add_arguments(parser)

        with pytest.raises(SystemExit):
            parser.parse_args(["--out", "keys", "--key-size", "1024"])

    def test_existing_files_without_force(self, tmp_path):
        """Test that existing files are detected without force flag."""
        # Create test files
        output_dir = tmp_path / "keys"
        output_dir.mkdir()
        (output_dir / "public.pem").touch()

        parser = argparse.ArgumentParser()
        KeygenArguments.add_arguments(parser)
        args = parser.parse_args(["--out", str(output_dir)])

        keygen_args = KeygenArguments()
        with pytest.raises(ValueError) as exc_info:
            keygen_args.process_arguments(args)
        assert "Use --force to overwrite" in str(exc_info.value)

    def test_key_paths(self, tmp_path):
        """Test that key paths are constructed correctly."""
        parser = argparse.ArgumentParser()
        KeygenArguments.add_arguments(parser)
        args = parser.parse_args(["--out", str(tmp_path)])

        keygen_args = KeygenArguments()
        keygen_args.process_arguments(args)

        assert keygen_args.public_key_path == tmp_path / "public.pem"
        assert keygen_args.private_key_path == tmp_path / "private.pem"


def test_cli_integration(tmp_path):
    """Integration test for CLI argument handling."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # Add keygen command
    keygen_parser = subparsers.add_parser("keygen")
    KeygenArguments.add_arguments(keygen_parser)

    # Test keygen command
    args = parser.parse_args(
        ["keygen", "--out", str(tmp_path), "--key-size", "2048", "--force"]
    )
    assert args.command == "keygen"
    assert args.output_dir == tmp_path
    assert args.key_size == 2048
    assert args.force
