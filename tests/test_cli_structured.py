import json
import sys
from pathlib import Path

from himacrypt.cli.main import main
from himacrypt.core import generate_rsa_keypair, write_keypair_to_dir


def run_cli(argv: list[str]) -> int:
    old = sys.argv
    try:
        sys.argv = ["himacrypt"] + argv
        try:
            return main()
        except SystemExit as e:
            # argparse may call sys.exit(); normalize to exit code
            return e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = old


def test_cli_json_multiple_keys_and_nested_selector(tmp_path: Path) -> None:
    data = {"a": {"b": {"secret": "s1"}}, "c": "keep"}
    inp = tmp_path / "in.json"
    out = tmp_path / "out.json"
    inp.write_text(json.dumps(data), encoding="utf-8")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / "in.json.enc"

    rc = run_cli(
        [
            "encrypt",
            "--in",
            str(inp),
            "--out",
            str(enc),
            "--public-key",
            str(keys / "public.pem"),
            "--format",
            "json",
            "--keys",
            "a.b.secret",
        ]
    )
    assert rc == 0

    rc = run_cli(
        [
            "decrypt",
            "--in",
            str(enc),
            "--out",
            str(out),
            "--private-key",
            str(keys / "private.pem"),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    got = json.loads(out.read_text(encoding="utf-8"))
    assert got["a"]["b"]["secret"] == "s1"


def test_cli_error_on_missing_input(tmp_path: Path) -> None:
    rc = run_cli(
        [
            "encrypt",
            "--in",
            str(tmp_path / "nope"),
            "--out",
            str(tmp_path / "o"),
            "--public-key",
            str(tmp_path / "pub.pem"),
        ]
    )
    assert rc == 2


def test_cli_toml_roundtrip(tmp_path: Path) -> None:
    try:
        import toml
    except Exception:  # pragma: no cover - environment may lack toml
        import pytest

        pytest.skip("toml not available")

    data = {"pkg": {"token": "tok"}}
    inp = tmp_path / "t.toml"
    out = tmp_path / "t.out.toml"
    inp.write_text(toml.dumps(data), encoding="utf-8")

    priv, pub = generate_rsa_keypair(key_size=2048)
    keys = tmp_path / "keys"
    write_keypair_to_dir(keys, priv, pub)

    enc = tmp_path / "t.toml.enc"
    rc = run_cli([
        "encrypt",
        "--in",
        str(inp),
        "--out",
        str(enc),
        "--public-key",
        str(keys / "public.pem"),
        "--format",
        "toml",
        "--keys",
        "pkg.token",
    ])
    assert rc == 0

    rc = run_cli([
        "decrypt",
        "--in",
        str(enc),
        "--out",
        str(out),
        "--private-key",
        str(keys / "private.pem"),
        "--format",
        "toml",
    ])
    assert rc == 0
    got = toml.loads(out.read_text(encoding="utf-8"))
    assert got["pkg"]["token"] == "tok"
