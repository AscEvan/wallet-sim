from __future__ import annotations

import hashlib
from bip32 import BIP32

from Crypto.Hash import RIPEMD160

_HARDENED_OFFSET = 2**31  # index harus < 2**31


def _check_index(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} harus int, bukan {type(value).__name__}")
    if not 0 <= value < _HARDENED_OFFSET:
        raise ValueError(f"{name} harus di rentang [0, 2**31), dapat {value}")

def _validate_path(path: str) -> None:
    parts = path.split('/')
    if len(parts) < 2 or parts[0] != 'm':
        raise ValueError(f'Path harus diawali "m/", dapat {path!r}')
    for segment in parts[1:]:
        num_str = segment[:-1] if segment.endswith(("'", "h", "H")) else segment 
        if not num_str.isdigit():
            raise ValueError(f"Segemen path tidak valid: {segment!r}")
        _check_index("path index", int(num_str))


def build_path(account: int = 0, index: int = 0, coin_type: int = 60) -> str:
    _check_index("account", account)
    _check_index("index", index)
    _check_index("coin_type", coin_type)
    return f"m/44'/{coin_type}'/{account}'/0/{index}"


def fingerprint(public_key: bytes) -> str:
    if len(public_key) != 33 or public_key[0] not in (0x02, 0x03):
        raise ValueError("public_key harus compressed: 33 byte berawalan 02/03")
    sha = hashlib.sha256(public_key).digest()
    return RIPEMD160.new(sha).digest()[:4].hex()

def derive_private_key(seed: bytes, path: str)-> bytes:
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("TypeError: Error Seed DataType")
    if not(16 <= len(seed) <= 64): 
        raise ValueError(f"ValueError: Len seed !=64; len : {len(seed)}")
    if not isinstance(path, str):
        raise TypeError(f'path harus str, bukan {type(path).__name__}')
    _validate_path(path)
    node = BIP32.from_seed(bytes(seed))

    return node.get_privkey_from_path(path)

