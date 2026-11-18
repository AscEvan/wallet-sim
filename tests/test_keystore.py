"""Test suite untuk wallet.crypto.keystore."""

from __future__ import annotations

import pathlib

import pytest
from wallet.crypto.keystore import (
    CIPHER_NAME,
    KDF_ITERATIONS,
    KDF_NAME,
    KEYSTORE_VERSION,
    InvalidPasswordError,
    KeystoreError,
    decrypt_secret,
    encrypt_secret,
    load_keystore,
    save_keystore,
)

# Gunakan iterasi kecil khusus di unit test agar eksekusi cepat,
# sambil tetap menguji nilai konstanta default produksi.
_TEST_ITERATIONS = 2_000
_SAMPLE_ADDR = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
_SAMPLE_EIP55 = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


def test_default_constants():
    assert KEYSTORE_VERSION == 1
    assert CIPHER_NAME == "fernet"
    assert KDF_NAME == "pbkdf2_hmac_sha256"
    assert KDF_ITERATIONS == 600_000


def test_encrypt_decrypt_roundtrip_and_unique_salt():
    secret = bytes.fromhex("1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727")
    password = "Correct-Horse-Battery-Staple!"

    ks1 = encrypt_secret(secret, password, _SAMPLE_ADDR, iterations=_TEST_ITERATIONS)
    ks2 = encrypt_secret(secret, password, _SAMPLE_ADDR, iterations=_TEST_ITERATIONS)

    assert ks1["version"] == KEYSTORE_VERSION
    assert ks1["address"] == _SAMPLE_EIP55
    assert ks1["crypto"]["cipher"] == CIPHER_NAME
    assert ks1["crypto"]["kdf"] == KDF_NAME
    assert ks1["crypto"]["kdfparams"]["iterations"] == _TEST_ITERATIONS

    # Salt dan ciphertext wajib berbeda setiap enkripsi
    assert ks1["crypto"]["kdfparams"]["salt"] != ks2["crypto"]["kdfparams"]["salt"]
    assert ks1["crypto"]["ciphertext"] != ks2["crypto"]["ciphertext"]

    assert decrypt_secret(ks1, password) == secret
    assert decrypt_secret(ks2, password) == secret


def test_wrong_password_raises_and_does_not_leak_secret():
    secret = b"seed-rahasia-64-byte" * 3
    good_pw = "PasswordBenar123"
    bad_pw = "PasswordSalah999"

    ks = encrypt_secret(secret, good_pw, _SAMPLE_EIP55, iterations=_TEST_ITERATIONS)
    with pytest.raises(InvalidPasswordError) as exc_info:
        decrypt_secret(ks, bad_pw)

    err_msg = str(exc_info.value)
    assert bad_pw not in err_msg
    assert good_pw not in err_msg


def test_save_and_load_keystore_atomic(tmp_path: pathlib.Path):
    secret = b"\x42" * 32
    password = "AtomicWritePass!"
    ks = encrypt_secret(secret, password, _SAMPLE_EIP55, iterations=_TEST_ITERATIONS)

    target = tmp_path / "keystores" / f"{_SAMPLE_EIP55}.json"
    save_keystore(ks, target)

    assert target.exists()
    # Pastikan tidak ada file sementara .tmp yang tertinggal
    assert list(target.parent.glob("*.tmp")) == []

    loaded = load_keystore(target)
    assert loaded == ks
    assert decrypt_secret(loaded, password) == secret


def test_corrupted_or_unsupported_keystore_rejected(tmp_path: pathlib.Path):
    secret = b"\x99" * 32
    ks = encrypt_secret(secret, "pw", _SAMPLE_EIP55, iterations=_TEST_ITERATIONS)

    # Versi tidak didukung
    bad_ver = {**ks, "version": 99}
    with pytest.raises(KeystoreError):
        decrypt_secret(bad_ver, "pw")

    # KDF tidak dikenal
    bad_kdf = {**ks, "crypto": {**ks["crypto"], "kdf": "md5"}}
    with pytest.raises(KeystoreError):
        decrypt_secret(bad_kdf, "pw")

    # File JSON rusak di disk
    broken_file = tmp_path / "broken.json"
    broken_file.write_text("{bukan json valid", encoding="utf-8")
    with pytest.raises(KeystoreError):
        load_keystore(broken_file)
