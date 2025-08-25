from pathlib import Path

from himacrypt.core import Encryptor, generate_rsa_keypair, write_keypair_to_dir


def test_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    # prepare sample .env file
    env = tmp_path / ".env"
    env.write_text("API_KEY=abc123\nDEBUG=False\n")

    # generate keypair
    private_pem, public_pem = generate_rsa_keypair(key_size=2048)
    keys_dir = tmp_path / "keys"
    write_keypair_to_dir(keys_dir, private_pem, public_pem)

    enc = tmp_path / ".env.enc"
    out = tmp_path / ".env.out"

    enc = tmp_path / ".env.enc"
    encryptor = Encryptor()
    encryptor.encrypt_env_file(env, enc, keys_dir / "public.pem")

    encryptor.decrypt_env_file(enc, out, keys_dir / "private.pem")

    assert out.read_bytes() == env.read_bytes()
