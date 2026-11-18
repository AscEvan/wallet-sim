"""Test suite untuk wallet.crypto.address terhadap test vector resmi EIP-55 dan BIP32."""

from __future__ import annotations

import json
import pathlib

import pytest
from wallet.crypto.address import (
    is_checksum_valid,
    is_valid,
    public_key_to_address,
    shorten,
    to_checksum,
    to_eip55,
)
from wallet.crypto.keys import PrivateKey

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "bip32_ethereum.json").read_text(encoding="utf-8")
)

EIP55_OFFICIAL_VECTORS = [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


def _rows():
    for case in VECTORS["cases"]:
        for entry in case["addresses"]:
            yield case, entry


_IDS = [f"{c['nama']}-{e['path'].rsplit('/', 1)[-1]}" for c, e in _rows()]


@pytest.mark.parametrize("vector", EIP55_OFFICIAL_VECTORS)
def test_eip55_official_vectors(vector):
    assert to_eip55(vector.lower()) == vector
    assert to_eip55("0X" + vector[2:].upper()) == vector
    assert to_checksum(vector[2:]) == vector
    assert is_valid(vector, require_eip55=True) is True
    assert is_checksum_valid(vector) is True


@pytest.mark.parametrize("case,entry", list(_rows()), ids=_IDS)
def test_public_key_to_address_all_formats(case, entry):
    expected = entry["address_eip55"]
    priv = PrivateKey.from_hex(entry["private_key"])
    pub_comp = bytes.fromhex(entry["public_key_compressed"])
    pub_uncomp = bytes.fromhex(entry["public_key_uncompressed"])
    pub_raw64 = pub_uncomp[1:]

    assert public_key_to_address(priv.public_key) == expected
    assert public_key_to_address(pub_comp) == expected
    assert public_key_to_address(pub_uncomp) == expected
    assert public_key_to_address(pub_raw64) == expected


def test_address_validation_and_typo_detection():
    valid_eip55 = "0xAbF4d0386bB7Ed2D7e6e7403E57f5c4b938f1dC9"
    lower_addr = valid_eip55.lower()
    upper_addr = "0x" + valid_eip55[2:].upper()
    # Ubah huruf pertama 'A' menjadi 'a' (merusak checksum mixed-case)
    corrupted_mixed = "0xabF4d0386bB7Ed2D7e6e7403E57f5c4b938f1dC9"

    assert is_valid(valid_eip55, require_eip55=False) is True
    assert is_valid(valid_eip55, require_eip55=True) is True

    assert is_valid(lower_addr, require_eip55=False) is True
    assert is_valid(lower_addr, require_eip55=True) is False
    assert is_checksum_valid(lower_addr) is False

    assert is_valid(upper_addr, require_eip55=False) is True
    assert is_valid(upper_addr, require_eip55=True) is False

    assert is_valid(corrupted_mixed, require_eip55=False) is False
    assert is_checksum_valid(corrupted_mixed) is False

    assert is_valid("0x1234") is False
    assert is_valid("AbF4d0386bB7Ed2D7e6e7403E57f5c4b938f1dC9") is False
    assert is_valid(12345) is False  # type: ignore[arg-type]


def test_shorten_address():
    addr = "0xAbF4d0386bB7Ed2D7e6e7403E57f5c4b938f1dC9"
    short = shorten(addr)
    assert short.startswith("0xAbF4")
    assert short.endswith("1dC9")

    with pytest.raises(ValueError):
        shorten("0xinvalid")
