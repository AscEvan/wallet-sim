"""Gate test: derivasi BIP32/BIP39/alamat harus cocok dengan test vector resmi."""

import json
import pathlib

import pytest
from mnemonic import Mnemonic
from bip32 import BIP32
from coincurve import PrivateKey
from Crypto.Hash import keccak

VECTORS_PATH = pathlib.Path(__file__).parent / "vectors" / "bip32_ethereum.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def to_eip55(address_hex: str) -> str:
    body = address_hex.lower().removeprefix("0x")
    digest = keccak.new(digest_bits=256, data=body.encode()).hexdigest()
    return "0x" + "".join(
        char.upper() if int(digest[i], 16) >= 8 else char
        for i, char in enumerate(body)
    )


def _rows():
    for case in VECTORS["cases"]:
        for entry in case["addresses"]:
            yield case, entry


# ---------- selftest EIP-55 (8 vektor resmi) ----------

def test_selftest_eip55():
    vectors = [
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]
    for v in vectors:
        assert to_eip55(v) == v


# ---------- konstanta kurva ----------

def test_curve_constants():
    assert VECTORS["kurva"]["nama"] == "secp256k1"
    assert int(VECTORS["kurva"]["order_hex"], 16) == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert int(VECTORS["kurva"]["half_order_hex"], 16) == 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


# ---------- mnemonic / seed ----------

@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["nama"])
def test_mnemonic_checksum_and_seed(case):
    mnemo = Mnemonic("english")
    assert mnemo.check(case["mnemonic"]) == case["checksum_valid"]
    seed = mnemo.to_seed(case["mnemonic"], passphrase=case["passphrase"])
    assert seed.hex() == case["seed_hex"]


# ---------- derivasi ----------

_IDS = [f"{c['nama']}-{e['path'].rsplit('/', 1)[-1]}" for c, e in _rows()]

@pytest.mark.parametrize("case,entry", list(_rows()), ids=_IDS)
def test_derive_matches_vector(case, entry):
    seed = bytes.fromhex(case["seed_hex"])
    node = BIP32.from_seed(seed)

    # get_privkey_from_path -> bytes (32 byte private key)
    priv = node.get_privkey_from_path(entry["path"])
    assert isinstance(priv, (bytes, bytearray))
    assert len(priv) == 32

    pub_unc = PrivateKey(priv).public_key.format(compressed=False)
    address = "0x" + keccak.new(digest_bits=256, data=pub_unc[1:]).digest()[-20:].hex()

    assert priv.hex() == entry["private_key"]
    assert pub_unc.hex() == entry["public_key_uncompressed"]
    assert PrivateKey(priv).public_key.format(compressed=True).hex() == entry["public_key_compressed"]
    assert address == entry["address"]
    assert to_eip55(address) == entry["address_eip55"]
    # xprv round-trip sanity: derivasi ulang dari xprv memberi private key yang sama
    xprv = node.get_xpriv_from_path(entry["path"])
    assert BIP32.from_xpriv(xprv).privkey == priv
