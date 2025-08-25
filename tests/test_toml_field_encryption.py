from pathlib import Path

import toml

from himacrypt.core import (
    Encryptor,
    generate_rsa_keypair,
    write_keypair_to_dir,
)


def test_toml_field_encryption_roundtrip(tmp_path: Path) -> None:
    data = {"tool": {"secret": "s3"}, "keep": "yes"}
    inp = tmp_path / "data.toml"
    out = tmp_path / "data.out.toml"
    inp.write_text(toml.dumps(data), encoding="utf-8")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / "data.toml.enc"
    encryptor = Encryptor()
    encryptor.encrypt_structured_file(
        inp,
        enc,
        keys / "public.pem",
        fmt="toml",
        selected_keys={"tool.secret"},
    )
    encryptor.decrypt_structured_file(
        enc, out, keys / "private.pem", fmt="toml"
    )
    got = toml.loads(out.read_text(encoding="utf-8"))
    assert got["tool"]["secret"] == "s3"
