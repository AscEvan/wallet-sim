# Tujuan: membungkus coincurve jadi antarmuka
#  yang tidak punya jebakan default.
# buat kunci, tanda tangani digest, verifikasi tanda tangan, dan cek low-S
# menerima digest 32 byte → menandatangani / memverifikasi,
# dengan semua jebakan library ditutup di satu tempat.


from __future__ import annotations

import hashlib
import coincurve as _cc                                                                               

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_ORDER = CURVE_ORDER // 2                                                                         


def _check_digest(digest: bytes) -> bytes:
    if not isinstance(digest, (bytes, bytearray)):
        raise TypeError(f'Digest harus berbentuk bytes, dapat : {type(digest)!r}')
    if len(digest) !=32 :
        raise ValueError(f"digest harus 32 bytes, dapat: {len(digest)}")
    return bytes(digest)

def message_hash(payload: bytes) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(f"payload harus bentuk bytes, dapat : {type(payload)}")
    return hashlib.sha256(payload).digest()

def parse_der(signature: bytes) -> tuple[int, int]: # DER signature
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError(f"signature harus bentuk bytes, dapat: {type(signature)!r}")

    if len(signature) < 8 or signature[0] != 0x30:
        raise ValueError("Format DER tidak valid: panjang < 8 atau bukan SEQUENCE (0x30)")

    # total_len harus sama persis dengan sisa byte (tolak trailing bytes)
    total_len = signature[1]
    if total_len != len(signature) - 2:
        raise ValueError(f"Panjang DER tidak cocok: tertulis {total_len}, aktual {len(signature) - 2}")

    # r
    if signature[2] != 0x02:
        raise ValueError("Format DER tidak valid: tag r bukan INTEGER (0x02)")
    r_len = signature[3]
    if r_len <= 0 or 4 + r_len + 2 > len(signature):
        raise ValueError("Format DER tidak valid: panjang r di luar batas")
    r_bytes = signature[4 : 4 + r_len]

    # s
    pos = 4 + r_len
    if signature[pos] != 0x02:
        raise ValueError("Format DER tidak valid: tag s bukan INTEGER (0x02)")
    s_len = signature[pos + 1]
    if s_len <= 0 or pos + 2 + s_len != len(signature):
        raise ValueError("Format DER tidak valid: panjang s tidak cocok dengan sisa signature")
    s_bytes = signature[pos + 2 :]

    # Validasi aturan DER signed INTEGER (Jebakan #2 Fase 1):
    # - Bit tertinggi menyala (>= 0x80) tanpa diawali 0x00 berarti negatif (tidak sah untuk ECDSA)
    # - Padding 0x00 di depan hanya sah jika byte berikutnya memiliki bit tertinggi menyala (>= 0x80)
    for name, b in (("r", r_bytes), ("s", s_bytes)):
        if b[0] >= 0x80:
            raise ValueError(f"Komponen {name} bernilai negatif dalam aturan DER")
        if len(b) > 1 and b[0] == 0x00 and b[1] < 0x80:
            raise ValueError(f"Komponen {name} memiliki padding 0x00 yang tidak perlu (non-canonical DER)")

    r = int.from_bytes(r_bytes, byteorder="big")
    s = int.from_bytes(s_bytes, byteorder="big")
    if not (1 <= r < CURVE_ORDER and 1 <= s < CURVE_ORDER):
        raise ValueError(f'r atau s berada di luar rentang [1, CURVE_ORDER]')
    return r, s

def is_low_s(signature: bytes) -> bool:
    # mengecek signature DER valid dan memiliki 1 <= s <= HALF_ORDER
    try:
        _, s = parse_der(signature)
    except ValueError:
        return False
    return 1 <= s <= HALF_ORDER


class PrivateKey:
    def __init__(self, inner: _cc.PrivateKey) -> None: 
        self._inner = inner
        if not isinstance(inner, _cc.PrivateKey):
            raise TypeError(f'inner harus bentuk PrivateKey, dapat: {type(inner)}')
    def __repr__(self) -> str:
        return "<PrivateKey [REDACTED]>"

    @classmethod
    def from_bytes(cls, raw: bytes) -> PrivateKey:
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f'raw harus bentuk bytes, dapat: {type(raw)}')
        if len(raw) != 32:
            raise ValueError(f'len raw harus 32, dapat: {len(raw)}')
        return cls(_cc.PrivateKey(bytes(raw)))

    @classmethod
    def from_hex(cls, hex_str: str) -> PrivateKey:
        if not isinstance(hex_str, str):
            raise TypeError(f'hex harus bentuk str, dapat: {type(hex_str)}')
        clean = hex_str.removeprefix('0x').removeprefix('0X')
        if len(clean) != 64:
            raise ValueError(f'panjang hex setelah remove prefix(0x) harus 64, dapat: {len(clean)}')
        try:
            raw = bytes.fromhex(clean)
        except ValueError:
            raise ValueError('hex private key tidak valid')
        return cls.from_bytes(raw)

    def to_hex(self) -> str: 
        return self._inner.secret.hex()

    def to_bytes(self) -> bytes:
        return self._inner.secret 

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self._inner.public_key)

    def public_bytes(self, compressed: bool = False) -> bytes: 
        return self._inner.public_key.format(compressed=compressed)

    def sign(self, digest: bytes) -> bytes:  # DER, low-S
        d = _check_digest(digest)
        sig = self._inner.sign(d, hasher = None)

        if not is_low_s(sig):
            raise RuntimeError('coincurve menghasilkan non-low-S')
        return sig
        
    # opsional
    def sign_recoverable(self, digest:bytes) -> bytes:  # 65 byte r||s||recid    
        d = _check_digest(digest)
        return self._inner.sign_recoverable(d, hasher=None)

class PublicKey:
    def __init__(self, inner: _cc.PublicKey) -> None:
        self._inner = inner
        if not isinstance(inner, _cc.PublicKey):
            raise TypeError(f'inner pubkey tidak sama typenya publickey. dapat: {type(inner)}')
    
    @classmethod
    def from_bytes(cls, raw: bytes) -> PublicKey: 
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f'raw pubkey harus bentuk key, dapat: {type(raw)}')
        if len(raw) not in(33, 65):
            raise ValueError(f'panjang raw pubkey, dapat: {len(raw)}')
        return cls(_cc.PublicKey(bytes(raw)))

    def to_bytes(self, compressed: bool = False) -> bytes:
        return self._inner.format(compressed=compressed)

    def verify(self, signature: bytes, digest: bytes) -> bool: 
        d = _check_digest(digest)

        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError(f'signature harus bentuk bytes, dapat: {type(signature)}')
        if not is_low_s(signature):
            return False

        return self._inner.verify(bytes(signature), d, hasher=None)
        
    @classmethod
    def recover(cls, recoverable_signature: bytes, digest: bytes) -> PublicKey: 
        d = _check_digest(digest)

        if not isinstance(recoverable_signature, (bytes, bytearray)):
            raise TypeError(f'recover signture harus bentuk bytes, dapat: {type(recoverable_signature)}')
        
        if len(recoverable_signature) != 65:
            raise ValueError(f'len recover signature harus 65, dapat: {len(recoverable_signature)}')
        
        s = int.from_bytes(recoverable_signature[32 : 64], "big")
        r = int.from_bytes(recoverable_signature[:32], 'big')

        if not (1 <= s <= HALF_ORDER):
            raise ValueError('recoverable signature harus low S')
        if not (1 <= r < CURVE_ORDER):
            raise ValueError('r di luar rentang [1, CURVE_ORDER]')

        return cls(_cc.PublicKey.from_signature_and_message(bytes(recoverable_signature), d, hasher=None))


