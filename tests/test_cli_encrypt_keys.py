import sys
from pathlib import Path

from himacrypt.cli.main import main
from himacrypt.core import generate_rsa_keypair, write_keypair_to_dir


def test_cli_encrypt_decrypt_with_keys(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("API_KEY=secret_value\nOTHER=keep\n")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / ".env.enc"
    out = tmp_path / ".env.out"

    # run encrypt CLI with --keys
    argv_backup = sys.argv
    sys.argv = [
        "himacrypt",
        "encrypt",
        "--in",
        str(env),
        "--out",
        str(enc),
        "--public-key",
        str(keys / "public.pem"),
        "--keys",
        "API_KEY",
    ]
    try:
        rc = main()
        assert rc == 0

        # run decrypt CLI
        sys.argv = [
            "himacrypt",
            "decrypt",
            "--in",
            str(enc),
            "--out",
            str(out),
            "--private-key",
            str(keys / "private.pem"),
        ]
        rc = main()
        assert rc == 0
    finally:
        sys.argv = argv_backup

    assert out.read_text() == env.read_text()
