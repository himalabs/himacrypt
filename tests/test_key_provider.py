from pathlib import Path

from himacrypt.key_provider import FileKeyProvider


def test_file_key_provider_provision(tmp_path: Path) -> None:
    kp_dir = tmp_path / "keys"
    provider = FileKeyProvider(kp_dir)

    priv_path, pub_path = provider.provision_keys(
        out_dir=kp_dir, key_size=2048
    )

    assert priv_path.exists()
    assert pub_path.exists()
    assert provider.get_private_key_path() == kp_dir / "private.pem"
    assert provider.get_public_key_path() == kp_dir / "public.pem"
