import sys
from pathlib import Path

from himacrypt.cli.main import main
from himacrypt.core import (
    Encryptor,
    generate_rsa_keypair,
    write_keypair_to_dir,
)


def test_cli_rotate_end_to_end(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("API_KEY=cli-rotate\n")

    # old keys
    old_priv, old_pub = generate_rsa_keypair(key_size=2048)
    old_dir = tmp_path / "old"
    write_keypair_to_dir(old_dir, old_priv, old_pub)

    # new keys
    new_priv, new_pub = generate_rsa_keypair(key_size=2048)
    new_dir = tmp_path / "new"
    write_keypair_to_dir(new_dir, new_priv, new_pub)

    enc = tmp_path / ".env.enc"
    encryptor = Encryptor()
    encryptor.encrypt_env_file(env, enc, old_dir / "public.pem")

    # run CLI
    sys_argv_backup = sys.argv
    sys.argv = [
        "himacrypt",
        "rotate",
        "--in-dir",
        str(tmp_path),
        "--old-private",
        str(old_dir / "private.pem"),
        "--new-public",
        str(new_dir / "public.pem"),
    ]
    try:
        rc = main()
        assert rc == 0
    finally:
        sys.argv = sys_argv_backup

    # decrypt with new private key
    out = tmp_path / ".env.out"
    encryptor.decrypt_env_file(enc, out, new_dir / "private.pem")
    assert out.read_text() == env.read_text()
