"""Test API wallet.crypto.mnemonic_hd terhadap test vector resmi."""

import json
import pathlib

import pytest
from wallet.crypto.bip39 import to_seed
from wallet.crypto.hd import build_path, derive_private_key

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "bip32_ethereum.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_build_path(index):
    assert build_path(account=0, index=index, coin_type=60) == f"m/44'/60'/0'/0/{index}"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["nama"])
@pytest.mark.parametrize("index", [0, 1, 2])
def test_derive_private_key_matches_vector(case, index):
    entry = case["addresses"][index]
    seed = bytes.fromhex(case["seed_hex"])
    path = entry["path"]
    priv = derive_private_key(seed, path)
    assert isinstance(priv, (bytes, bytearray))
    assert priv.hex() == entry["private_key"]
    assert to_seed(case["mnemonic"], case["passphrase"]).hex() == case["seed_hex"]
