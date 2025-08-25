"""Command-line arguments for himacrypt CLI."""

from .decrypt import DecryptArguments
from .encrypt import EncryptArguments
from .keygen import KeygenArguments
from .lint import LintArguments
from .rotate import RotateArguments

__all__ = [
    "DecryptArguments",
    "EncryptArguments",
    "KeygenArguments",
    "LintArguments",
    "RotateArguments",
]
