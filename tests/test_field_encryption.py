from pathlib import Path

from himacrypt.core import (
    Encryptor,
    generate_rsa_keypair,
    write_keypair_to_dir,
)


def test_field_level_encrypt_decrypt_env(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("API_KEY=secret\nDEBUG=False\n")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / ".env.enc"
    encryptor = Encryptor()
    encryptor.encrypt_env_file(
        env, enc, keys / "public.pem", selected_keys={"API_KEY"}
    )

    out = tmp_path / ".env.out"
    encryptor.decrypt_env_file(enc, out, keys / "private.pem")

    assert out.read_text() == env.read_text()
