from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import os
from cryptography.fernet import Fernet, InvalidToken
from wallet.crypto.address import to_eip55

KEYSTORE_VERSION = 1
CIPHER_NAME = 'fernet'
KDF_NAME =  'pbkdf2_hmac_sha256'
KDF_ITERATIONS = 600_000
SALT_BYTES = 16


class KeystoreError(ValueError):
    """ Format atau versi keystore tidak valid / rusak """

class InvalidPasswordError(KeystoreError):
    """Password salah atau autentikasi HMAC Fernet gagal"""

'''
enurunkan kunci 32 byte dari password +
  salt memakai PBKDF2-HMAC-SHA256, lalu
  mengubahnya ke format base64 url-safe yang
  diminta oleh Fernet.
'''
def _derive_fernet_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    # validasi password
    if not isinstance(password, str):
        raise TypeError(f"password harus str, dapat: {type(password).__name__}")
    if not password:
        raise ValueError("password tidak boleh kosong")

    # validasi salt
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError(f"salt harus bytes, dapat: {type(salt).__name__}")
    if len(salt) != SALT_BYTES:
        raise ValueError(f"panjang salt harus {SALT_BYTES} byte, dapat: {len(salt)}")

    # validasi iterations (bool adalah subclass dari int di Python!)
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise TypeError(f"iterations harus int, dapat: {type(iterations).__name__}")
    if iterations <= 0:
        raise ValueError(f"iterations harus > 0, dapat: {iterations}")

    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        bytes(salt),
        iterations, 
        dklen=32
    )

    return base64.urlsafe_b64encode(dk)

'''
Mengenkripsi secret (bytes) dengan salt
  acak baru 16 byte dan mengembalikan dict
  struktur Keystore v1.
'''
def encrypt_secret(secret: bytes, password: str, address: str, *, iterations: int = KDF_ITERATIONS) -> dict:
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError(f'secret harus bentuk bytes, dapat: {type(secret)}')
    if len(secret) <= 0:
        raise ValueError(f'panjang secret harus > 0, dapat: {len(secret)}')
    
    checksum_addr = to_eip55(address)
    salt = os.urandom(SALT_BYTES)
    key = _derive_fernet_key(password, salt, iterations)
    token = Fernet(key).encrypt(bytes(secret)).decode('ascii')

    return {
        'version' : KEYSTORE_VERSION,
        'address' : checksum_addr,
        'crypto' : {
            'cipher' : CIPHER_NAME,
            'ciphertext': token,
            'kdf' : KDF_NAME,
            'kdfparams' : {
                'iterations' : iterations,
                'salt' : salt.hex()
            }
        }
    }


'''
validasi skema keystore_data dan
  mendekripsi ciphertext kembali menjadi bytes
  rahasia
'''
def decrypt_secret(keystore_data: dict, password: str) -> bytes:
    if not isinstance(keystore_data, dict):
        raise TypeError(f'keystore_data harus bentuk dict, dapat: {type(keystore_data)}')
    if keystore_data.get('version') != KEYSTORE_VERSION:
        raise KeystoreError()
    try:
        crypto = keystore_data['crypto']
        cipher = crypto['cipher']
        kdf = crypto['kdf']
        kdfparams = crypto['kdfparams']
        salt = bytes.fromhex(kdfparams['salt'])
        iterations = kdfparams['iterations']
        ciphertext = crypto['ciphertext']
    except(KeyError, TypeError, ValueError ) as err:
        raise KeystoreError('struktur keystore tidak valid') from err

    if cipher != CIPHER_NAME or kdf != KDF_NAME or not isinstance(ciphertext, str):
        raise KeystoreError('cipher, kdf, atau ciphertext tidak valid')

    key = _derive_fernet_key(password, salt, iterations)
    try:
        return Fernet(key).decrypt(ciphertext.encode('ascii'))
    except InvalidToken as err:
        raise InvalidPasswordError('password salah atau ciphertext rusak') from err 


def save_keystore(keystore_data: dict, path: str | pathlib.Path) -> None:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_suffix(target.suffix + ".tmp")

    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(keystore_data, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, target)

def load_keystore(path: str | pathlib.Path) -> dict:
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))

    except json.JSONDecodeError:
        raise KeystoreError()

    if not isinstance(data, dict) or data.get('version') != KEYSTORE_VERSION:
        raise KeystoreError('format atau versi keystore tidak valid')
    
    return data
