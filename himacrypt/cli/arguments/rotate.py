from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RotateArguments:
    in_dir: Path = Path(".")
    pattern: str = "*.enc"
    old_private: Optional[Path] = None
    new_public: Optional[Path] = None
    backup: bool = True

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--in-dir",
            "-i",
            required=True,
            help="Directory with encrypted files to rotate",
        )
        parser.add_argument(
            "--pattern",
            default="*.enc",
            help="Glob pattern for files to rotate",
        )
        parser.add_argument(
            "--old-private", required=True, help="Path to old private key PEM"
        )
        parser.add_argument(
            "--new-public", required=True, help="Path to new public key PEM"
        )
        parser.add_argument(
            "--no-backup",
            dest="backup",
            action="store_false",
            help="Do not keep backups",
        )

    def process_arguments(self, args: argparse.Namespace) -> None:
        self.in_dir = Path(args.in_dir)
        self.pattern = args.pattern
        self.old_private = Path(args.old_private)
        self.new_public = Path(args.new_public)
        self.backup = bool(getattr(args, "backup", True))
