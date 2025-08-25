import json
from pathlib import Path

import pytest

from himacrypt.core import (
    Encryptor,
    generate_rsa_keypair,
    write_keypair_to_dir,
)


def test_json_field_encryption_roundtrip(tmp_path: Path) -> None:
    data = {"api": {"key": "secret", "other": 1}, "top": "keep"}
    inp = tmp_path / "data.json"
    out = tmp_path / "data.out.json"
    enc = tmp_path / "data.enc.json"
    inp.write_text(json.dumps(data), encoding="utf-8")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / "data.json.enc"
    encryptor = Encryptor()
    encryptor.encrypt_structured_file(
        inp, enc, keys / "public.pem", fmt="json", selected_keys={"api.key"}
    )
    # decrypt
    encryptor.decrypt_structured_file(
        enc, out, keys / "private.pem", fmt="json"
    )
    got = json.loads(out.read_text(encoding="utf-8"))
    assert got["api"]["key"] == "secret"
    assert got["top"] == "keep"


def test_yaml_field_encryption_roundtrip(tmp_path: Path) -> None:
    try:
        import yaml
    except Exception:  # pragma: no cover - environment may lack PyYAML
        pytest.skip("PyYAML not available")

    data = {"service": {"token": "ttt"}, "keep": True}
    inp = tmp_path / "data.yaml"
    out = tmp_path / "data.out.yaml"
    inp.write_text(yaml.safe_dump(data), encoding="utf-8")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / "data.yaml.enc"
    encryptor = Encryptor()
    encryptor.encrypt_structured_file(
        inp,
        enc,
        keys / "public.pem",
        fmt="yaml",
        selected_keys={"service.token"},
    )
    encryptor.decrypt_structured_file(
        enc, out, keys / "private.pem", fmt="yaml"
    )
    got_text = out.read_text(encoding="utf-8")
    assert "ttt" in got_text
