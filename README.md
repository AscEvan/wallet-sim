# wallet-sim

Simulasi aplikasi **wallet kripto** untuk keperluan edukatif — bagaimana dompet digital
sebenarnya bekerja di balik layar: derivasi kunci, keystore terenkripsi, penandatanganan
transaksi, dan ledger.

> **Peringatan:** ini **simulasi**, bukan implementasi produksi. Jangan pernah
> menggunakan kode ini untuk Holds dana sungguhan. lihat `SECURITY.md`.

---

## Fitur

- **BIP39** — generate & validasi seed phrase 12/24 kata, plus passphrase opsional
- **BIP32** — derivasi `m/44'/60'/0'/0/index` dari seed yang sama
- **Address Ethereum-style** — `keccak-256(pubkey)[-20:]` dengan checksum **EIP-55**
- **Keystore terenkripsi** — PBKDF2-HMAC-SHA256 (600.000 iterasi) + Fernet, atomic write
- **Transaksi** — canonical JSON, SHA-256 eksplisit, ECDSA low-S, nonce anti-replay
- **Ledger** — account model, 7 lapis validasi, anti-double-spend, `faucet` untuk pengujian
- **Harga coin opsional** — CoinMarketCap; degrade ke `N/A` bila offline / tanpa API key

## Prasyarat

- Python **3.11+** (diuji sampai 3.13)

## Instalasi

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Menjalankan

```bash
python main.py
```

Alternatif, setelah `pip install -e .`:

```bash
wallet
```

## Konfigurasi

Salin `.env.example` menjadi `.env` bila ingin fitur harga coin:

```bash
cp .env.example .env
```

Tanpa `API_KEY`, aplikasi tetap berjalan penuh — hanya kolom harga yang tampil `N/A`.

## Testing

```bash
pytest
```

Test vector di `tests/vectors/` adalah **gate**: derivasi alamat dan tanda tangan
harus cocok dengannya sebelum fitur lain dianggap benar.

## Struktur

```
wallet/
├── config.py          # parameter chain, metadata koin, fee
├── storage.py         # baca/tulis JSON atomik + versioning
├── account.py         # class Wallet
├── transaction.py     # payload kanonik, sign, verify
├── crypto/
│   ├── bip39.py       # BIP39
│   ├── hd.py          # BIP32
│   ├── keys.py        # coincurve (secp256k1)
│   ├── address.py     # keccak-256 + EIP-55
│   └── keystore.py    # PBKDF2 + Fernet
├── ledger/
│   ├── ledger.py      # saldo + validasi
│   ├── mempool.py     # antrean pending
│   └── node.py        # façade: submit / commit / balance
├── pricing.py         # CoinMarketCap (opsional)
└── ui/                # console, app, views

data/                  # runtime (gitignored)
├── index.json         # daftar wallet
├── keystores/         # <address>.json, terenkripsi
└── ledger.json
```

## Riwayat

`_archive/` berisi implementasi versi lama beserta catatan bug-nya. Tidak di-versioned.

## Lisensi

MIT — untuk pembelajaran.