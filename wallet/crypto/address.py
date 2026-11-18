'''
  Mengubah PublicKey (dari wallet/crypto/keys.py) atau bytes
  public key menjadi alamat Ethereum (0x + 40 hex) ber-
  checksum EIP-55 menggunakan Keccak-256 asli
'''

from __future__ import annotations

from Crypto.Hash import keccak
from wallet.crypto.keys import PublicKey


def to_eip55(address_hex : str) -> str:
    if not isinstance(address_hex, str):
        raise TypeError(f'address_hex harus bentuk str, dapat: {type(address_hex)}')
    # kupas prefix
    body = address_hex.removeprefix('0x').removeprefix('0X').lower() 

    try:
        if len(body) != 40 or len(bytes.fromhex(body)) != 20:
            raise ValueError
    except ValueError as err:
        raise ValueError(
            f"Address tidak valid: body harus tepat 40 karakter heksadesimal (0-9, a-f), dapat: {body!r}"
        ) from err

    digest = keccak.new(digest_bits=256, data=body.encode('ascii')).hexdigest()

    return "0x" + "".join(
        char.upper() if int(digest[i], 16) >= 8 else char
        for i, char in enumerate(body)
    )


def to_checksum(address: str) -> str:       # EIP-55 mixed case
    return to_eip55(address)

def is_checksum_valid(address: str) -> bool: 
    return is_valid(address, require_eip55=True)

# cek apakah sebuah string adalah alamat Ethereum yang valid
def is_valid(address: str, *, require_eip55: bool = False) -> bool:
    if not isinstance(address, str):
        return False
    if not address.startswith('0x') or len(address) != 42:
        return False

    body = address[2:] 
    try:
        if len(bytes.fromhex(body)) != 20:
            return False
    except ValueError:
        return False
    
    if require_eip55 == True:
        return address == to_eip55(address)
    if body == body.lower() or body == body.upper(): 
        return True
    
    return address == to_eip55(address)


def shorten(address: str) -> str:       # "0xAbF4…1dC9"
    if not is_valid(address):
        raise ValueError('address tidak valid')
    return f'{address[:6]}...{address[-4:]}'


def public_key_to_address(public_key: bytes | PublicKey) -> str:
    if isinstance(public_key, PublicKey):
        uncompressed = public_key.to_bytes(compressed=False)
    elif isinstance(public_key, (bytes, bytearray)):
        raw_bytes = bytes(public_key)
        if len(raw_bytes) == 64:
            raw_bytes = b"\x04" + raw_bytes
        uncompressed = PublicKey.from_bytes(raw_bytes).to_bytes(compressed=False)

    else:
        raise TypeError(f'public_key harus bentuk bytes/PublicKey, dapat: {type(public_key)}')

    raw_64 = uncompressed[1:]
    digest = keccak.new(digest_bits=256, data = raw_64).digest()

    return to_eip55(digest[-20:].hex())
    



