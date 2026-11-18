"""Test suite untuk wallet.crypto.keys terhadap test vector resmi dan aturan keamanan."""

from __future__ import annotations

import json
import pathlib

import pytest
from wallet.crypto.keys import (
    CURVE_ORDER,
    HALF_ORDER,
    PrivateKey,
    PublicKey,
    is_low_s,
    message_hash,
    parse_der,
)

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "bip32_ethereum.json").read_text(encoding="utf-8")
)


def _rows():
    for case in VECTORS["cases"]:
        for entry in case["addresses"]:
            yield case, entry


_IDS = [f"{c['nama']}-{e['path'].rsplit('/', 1)[-1]}" for c, e in _rows()]


def _encode_der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def _encode_der(r: int, s: int) -> bytes:
    body = _encode_der_int(r) + _encode_der_int(s)
    return b"\x30" + bytes([len(body)]) + body


@pytest.mark.parametrize("case,entry", list(_rows()), ids=_IDS)
def test_keypair_matches_official_vectors(case, entry):
    priv = PrivateKey.from_hex(entry["private_key"])
    assert priv.to_hex() == entry["private_key"]
    assert priv.to_bytes() == bytes.fromhex(entry["private_key"])
    assert priv.public_bytes(compressed=False).hex() == entry["public_key_uncompressed"]
    assert priv.public_bytes(compressed=True).hex() == entry["public_key_compressed"]
    assert priv.public_key.to_bytes(compressed=False).hex() == entry["public_key_uncompressed"]
    assert priv.public_key.to_bytes(compressed=True).hex() == entry["public_key_compressed"]


def test_private_key_repr_redacts_secret():
    secret_hex = VECTORS["cases"][0]["addresses"][0]["private_key"]
    priv = PrivateKey.from_hex("0x" + secret_hex)
    assert secret_hex not in repr(priv)
    assert secret_hex not in str(priv)
    assert "REDACTED" in repr(priv)


def test_sign_verify_and_low_s():
    priv = PrivateKey.from_hex(VECTORS["cases"][0]["addresses"][0]["private_key"])
    digest = message_hash(b"payload transaksi kanonik")

    sig = priv.sign(digest)
    assert is_low_s(sig) is True
    assert priv.public_key.verify(sig, digest) is True
    assert priv.public_key.verify(sig, message_hash(b"payload diubah")) is False


def test_high_s_signature_is_rejected():
    priv = PrivateKey.from_hex(VECTORS["cases"][0]["addresses"][0]["private_key"])
    digest = message_hash(b"uji anti-malleability low-S")

    sig = priv.sign(digest)
    r, s = parse_der(sig)
    s_high = CURVE_ORDER - s
    assert s_high > HALF_ORDER

    malleated_sig = _encode_der(r, s_high)
    assert parse_der(malleated_sig) == (r, s_high)
    assert is_low_s(malleated_sig) is False
    assert priv.public_key.verify(malleated_sig, digest) is False


def test_malformed_der_and_digest_validation():
    priv = PrivateKey.from_hex(VECTORS["cases"][0]["addresses"][0]["private_key"])
    digest = message_hash(b"valid digest")
    sig = priv.sign(digest)

    # Trailing byte pada DER harus ditolak
    assert is_low_s(sig + b"\x00") is False
    assert priv.public_key.verify(sig + b"\x00", digest) is False
    assert priv.public_key.verify(b"bukan-der", digest) is False

    # Digest bukan 32 byte harus melempar ValueError (Aturan 4)
    with pytest.raises(ValueError):
        priv.sign(b"pesan mentah belum di-hash")
    with pytest.raises(ValueError):
        priv.public_key.verify(sig, b"digest pendek")


def test_recoverable_signature_roundtrip_and_high_s():
    priv = PrivateKey.from_hex(VECTORS["cases"][0]["addresses"][0]["private_key"])
    digest = message_hash(b"recoverable test")

    rec_sig = priv.sign_recoverable(digest)
    assert len(rec_sig) == 65
    recovered = PublicKey.recover(rec_sig, digest)
    assert recovered.to_bytes(compressed=True) == priv.public_bytes(compressed=True)

    # Ubah s menjadi high-S pada recoverable signature -> wajib ditolak
    r_bytes = rec_sig[:32]
    s = int.from_bytes(rec_sig[32:64], "big")
    recid = rec_sig[64:]
    high_s_bytes = (CURVE_ORDER - s).to_bytes(32, "big")
    with pytest.raises(ValueError):
        PublicKey.recover(r_bytes + high_s_bytes + recid, digest)
