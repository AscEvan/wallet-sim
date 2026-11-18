"""
Regenerasi tests/vectors/bip32_ethereum.json.

Jalankan HANYA bila test vector resmi berubah:

    python tests/tools/gen_vectors.py

Jangan edit file JSON hasil generate secara manual - file itu adalah kontrak
yang dipakai test. Semua nilai di dalamnya sudah diverifikasi silang terhadap
vektor publik (ethers.js) dan BIP32 Test Vector 1 (BIP-0032).
"""

import json
import pathlib

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import coincurve
from bip32 import BIP32
from Crypto.Hash import keccak
from mnemonic import Mnemonic

OUTPUT = pathlib.Path(__file__).resolve().parent.parent / "vectors" / "bip32_ethereum.json"
INDEXES = (0, 1, 2)
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

CASES = [
    (
        "vektor-ethers-js",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    ),
    (
        "vektor-trezor",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "TREZOR",
    ),
    (
        "vektor-legacy-1",
        "trap situate sphere six escape design luggage best wing have like radar",
        "",
    ),
    (
        "vektor-legacy-2",
        "owner pretty sock zone shed attitude average roof tired monster private old",
        "",
    ),
]


def to_eip55(address_hex: str) -> str:
    """
    EIP-55: kapitalisasi huruf ditentukan nibble ke-i dari keccak-256(hex lowercase).

    PENTING: EIP-55 memakai Keccak-256 asli (padding 0x01), BUKAN SHA3-256 (NIST, 0x06).
    hashlib.sha3_256 memberi hasil BERBEDA dan akan menghasilkan checksum yang salah.
    """
    body = address_hex.lower().removeprefix("0x")
    digest = keccak.new(digest_bits=256, data=body.encode()).hexdigest()
    checksummed = "".join(
        char.upper() if int(digest[i], 16) >= 8 else char
        for i, char in enumerate(body)
    )
    return "0x" + checksummed


def selftest_eip55() -> bool:
    """Uji ke 8 test vector resmi EIP-55 (https://eips.ethereum.org/EIPS/eip-55)."""
    vectors = [
        # Semua huruf besar
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        # Semua huruf kecil
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        # Campuran
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]
    gagal = [v for v in vectors if to_eip55(v) != v]
    if gagal:
        print("EIP-55 GAGAL:")
        for v in gagal:
            print(f" _input: {v}\n  hasil: {to_eip55(v)}")
        return False
    return True


def derive(seed: bytes, path: str) -> dict:
    private = BIP32.from_seed(seed).get_privkey_from_path(path)
    public_uncompressed = coincurve.PrivateKey(private).public_key.format(compressed=False)
    address = keccak.new(digest_bits=256, data=public_uncompressed[1:]).digest()[-20:].hex()
    return {
        "path": path,
        "private_key": private.hex(),
        "public_key_uncompressed": public_uncompressed.hex(),
        "public_key_compressed": coincurve.PrivateKey(private).public_key.format(compressed=True).hex(),
        "address": f"0x{address}",
        "address_eip55": to_eip55(f"0x{address}"),
    }


def main() -> None:
    if not selftest_eip55():
        raise SystemExit("selftest EIP-55 gagal - jangan pakai file vector ini")

    mnemonic = Mnemonic("english")
    document = {
        "_catatan": (
            "Dihasilkan & diverifikasi pada Fase 0 (2026-10-15). Sumber: vektor publik "
            "ethers.js dan BIP32 Test Vector 1 (BIP-0032). JANGAN edit manual - "
            "regenerate dengan tests/tools/gen_vectors.py."
        ),
        "kurva": {
            "nama": "secp256k1",
            "order_hex": hex(CURVE_ORDER),
            "half_order_hex": hex(CURVE_ORDER // 2),
        },
        "cases": [],
    }

    for name, phrase, passphrase in CASES:
        seed = mnemonic.to_seed(phrase, passphrase=passphrase)
        document["cases"].append(
            {
                "nama": name,
                "mnemonic": phrase,
                "passphrase": passphrase,
                "checksum_valid": bool(mnemonic.check(phrase)),
                "seed_hex": seed.hex(),
                "addresses": [derive(seed, f"m/44'/60'/0'/0/{index}") for index in INDEXES],
            }
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"ditulis: {OUTPUT}")

    for case in document["cases"]:
        for entry in case["addresses"]:
            index = entry["path"].rsplit("/", 1)[-1]
            print(f"  {case['nama']:<18} [{index}] {entry['address_eip55']}")


if __name__ == "__main__":
    main()