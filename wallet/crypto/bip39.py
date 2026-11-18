
# Before : mnemonic.py;
# After  : bip39.py
'''
!!!!
ETH STYLE
!!!!
'''

from __future__ import annotations

from mnemonic import Mnemonic as _Mnemonic

STRENGTH_12 = 128
STRENGTH_24 = 256

_VALID_STRENGTHS = (STRENGTH_12, STRENGTH_24)
_MNEMO = _Mnemonic("english")  # mahal dibuat: satu instance per modul


def normalize(phrase: str) -> str:
    """Lowercase + collapse semua whitespace (spasi, tab, newline, NBSP) jadi satu spasi."""
    return " ".join(phrase.lower().split())


def generate(strength: int = STRENGTH_12) -> str:
    if strength not in _VALID_STRENGTHS:
        raise ValueError(f"strength harus {STRENGTH_12} atau {STRENGTH_24}\ntype: {type(strength)}")
    return _MNEMO.generate(strength)


def validate(phrase: str) -> bool:
    if not isinstance(phrase, str):
        return False
    return _MNEMO.check(normalize(phrase))


def word_count(phrase: str) -> int:
    return len(normalize(phrase).split())


def to_seed(phrase: str, passphrase: str = "") -> bytes:
    normalized = normalize(phrase)
    if not _MNEMO.check(normalized):
        # pesan sengaja tidak memuat phrase (aturan 6)
        raise ValueError("mnemonic tidak valid (kata di luar wordlist atau checksum salah)")
    return _MNEMO.to_seed(normalized, passphrase)  # passphrase TIDAK dinormalisasi