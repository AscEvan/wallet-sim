# Catatan Teknis — Hasil Verifikasi Fase 0

Semua fakta di dokumen ini **sudah diuji langsung** di environment ini
(Python 3.13.5, venv di `.venv/`), bukan asumsi. Fase 1 tidak perlu menebak
perilaku library.

---

## 1. Bug yang ketahuan: EIP-55 memakai Keccak-256, bukan SHA3-256

Ini temuan paling penting di Fase 0.

Implementasi pertama `to_eip55()` memakai `hashlib.sha3_256`. Itu **salah** dan
menghasilkan checksum yang berbeda dari standar Ethereum.

Perbedaannya bukan kebetulan — dua fungsi itu memang berbeda:

| | Keccak-256 | SHA3-256 |
|---|---|---|
| Standar | Ethereum (original Keccak) | NIST FIPS 202 |
| Padding | `0x01` | `0x06` |
| Library | `Crypto.Hash.keccak` (pycryptodome) | `hashlib.sha3_256` |

Kode yang benar:

```python
from Crypto.Hash import keccak

def to_eip55(address_hex: str) -> str:
    body = address_hex.lower().removeprefix("0x")
    digest = keccak.new(digest_bits=256, data=body.encode()).hexdigest()
    return "0x" + "".join(
        char.upper() if int(digest[i], 16) >= 8 else char
        for i, char in enumerate(body)
    )
```

**Semua 8 test vector resmi EIP-55 lolos** dengan implementasi ini
(`selftest_eip55()` di `tests/tools/gen_vectors.py`).

> Kalau ini tidak diuji terhadap vektor resmi, address tetap akan "terlihat
> benar" (format `0x` + 40 hex + huruf campur) tapi akan **tidak cocok** dengan
> address yang dihasilkan wallet Ethereum sungguhan.

---

## 2. `coincurve` — jebakan `hasher` bawaan

`coincurve` 20.0.0. API yang terverifikasi:

| Metode | Perilaku |
|---|---|
| `PrivateKey.sign(msg, hasher=sha256)` | `hasher` **default = sha256**. Mengembalikan **DER** (70–72 byte, bukan 64). |
| `PublicKey.verify(sig, msg, hasher=sha256)` | Membutuhkan signature **DER**. Mengembalikan `bool`. |
| `PublicKey.format(compressed=True/False)` | 33 byte compressed / 65 byte uncompressed (prefix `0x04`). |
| `PublicKey.from_signature_and_message(...)` | Recovery pubkey dari signature. |
| `PrivateKey.sign_recoverable(...)` | 65 byte `r‖s‖v`. |

Bukti jebakannya:

```python
digest = sha256(msg)                      # kita hash sendiri
pk.sign(digest, hasher=None)              # hasher=None -> digest dipakai apa adanya
pk.public_key.verify(sig, digest, hasher=None)   # -> True
pk.public_key.verify(sig, digest)                # -> False  (hash dua kali!)
```

**Keputusan Fase 1:** Selalu hash di lapisan kita sendiri dan teruskan
`hasher=None`. Tidak ada default tersembunyi yang bisa diam-diam berubah.

> Inilah persis bug di kode lama: `wallet.py` memanggil
> `sign(payload)` tanpa `hashfunc`, sehingga `ecdsa` memakai **SHA-1** secara
> default, sedangkan `TestCase1.py` dan `node.py` mengasumsikan SHA-256.
> Ketiganya tidak akan pernah cocok.

### DER, bukan compact

`sign()` mengembalikan DER dan `verify()` memangaternity menerima DER, jadi
tidak perlu konversi. Untuk mem-parsing `r` dan `s` (low-S check) kita butuh
DER parser sendiri — **jangan** pakai `asn1crypto`, itu hanya dependensi
transitif dan tidak ada di `requirements.txt`.

---

## 3. Order kurva secp256k1

Tidak diekspos sebagai `coincurve.ecdsa.N`. Nilainya harus ditetapkan eksplisit
dan **sudah diverifikasi** lewat dua pembuktian independen:

```
N   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
```

Pembuktian:
1. `coincurve.PrivateKey(N)` → **`ValueError`**. Private key di luar `[1, N-1]` benar-benar ditolak.
2. `(N-1)·G` menghasilkan public key ber-prefix `0x03`, sedangkan `G` ber-prefix `0x02` — keduanya adalah titik yang sama dengan Y di-negasi, persis sifat `N-1 ≡ -1 (mod N)`.

---

## 4. `bip32` 5.0.0 — nama metode berbeda dari dugaan

Bukan `to_extended_key()`. Metode yang tersedia:

```
from_seed, from_xpriv, from_xpub
get_privkey_from_path, get_pubkey_from_path
get_xpriv, get_xpub, get_xpriv_from_path, get_xpub_from_path
get_xpriv_bytes, get_xpub_bytes, get_extended_privkey_from_path, get_extended_pubkey_from_path
get_fingerprint
```

`get_xpriv_from_path(path)` mengembalikan string `xprv...` (base58check).

**Semua test vector resmi BIP32 Test Vector 1 lolos** (`m`, `m/0'`, `m/0'/1`, `m/0'/1/2'`)
dengan seed `000102030405060708090a0b0c0d0e0f`.

---

## 5. Derivasi BIP39 → BIP32 → address **terbukti benar**

Rantai `mnemonic` → `BIP32` → `keccak(pubkey)[-20:]` menghasilkan:

| Input | Index | Address |
|---|---|---|
| `abandon … about`, passphrase `""` | 0 | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| `abandon … about`, passphrase `TREZOR` | 0 | `0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6` |
| `trap situate sphere … radar` | 0 | `0xAbF4d0386bB7Ed2D7e6e7403E57f5c4b938f1dC9` |
| `owner pretty sock … old` | 0 | `0x0044aDa69CA7347748A580F86a129f02CdFA9017` |

Dua baris terakhir **persis cocok** dengan `keyStorage.json` dan `stateLedger.json`
di kode lama. Artinya logika derivasi di `_address.py` lama ternyata **benar** —
bug-nya ada di signing, import, dan struktur, bukan di derivasi.

> Catatan: address `0x9858…` berasal dari passphrase **kosong**, bukan `TREZOR`.
> Itu sumber kekeliruan pertama saat verifikasi Fase 0.

---

## 6. Environment

```
Python           3.13.5
mnemonic         0.21
bip32            5.0.0
coincurve        20.0.0
base58           2.1.1
pycryptodome     3.23.0
cryptography     50.0.2   (naik dari 41.0.7 yang tidak punya wheel py3.13)
requests         2.31.0
pytest           9.1.1
ecdsa            DIHAPIS dari venv - membuktikan kode baru tidak bergantung padanya
```

`cryptography==41.0.7` di `requirements.txt` lama **tidak punya wheel** untuk
Python 3.13. Venv lama kebetulan jalan karena paketnya sudah terpasang manual.

---

## 7. Jebakan yang harus dihindari di Fase 1

- Jangan pakai `hashlib.sha3_256` untuk apa pun yang resembling Ethereum.
- Jangan membiarkan `hasher`/`hashfunc` pakai default.
- Jangan andalkan `asn1crypto` (dependensi transitif, tidak dideklarasikan).
- Jangan menulis konstanta kurva tanpa menyertakan pembuktiannya.
- Setiap nilai yang memengaruhi perilaku harus punya test vector resmi —
  bukan hanya test yang menulis ulang logikanya sendiri (itu circular).