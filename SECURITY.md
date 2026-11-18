# Keamanan

## Proyek ini adalah simulasi

Tujuan proyek ini adalah **pemahaman edukatif** tentang bagaimana dompet kripto bekerja:
derivasi kunci, enkripsi, penandatanganan, dan ledger. Ini **bukan** implementasi
dompet yang aman untuk dana sungguhan.

## Jangan gunakan untuk dana nyata

Hal-hal berikut **tidak** diimplementasikan:

- **Proteksi brute-force yang sesungguhnya.** Pembatasan percobaan login hanya ada di
  memori proses; bisa di-reset dengan menutup aplikasi.
- **KDF memory-hard.** Proyek ini memakai PBKDF2-HMAC-SHA256. Untuk standar 2026,
  `Argon2id` atau `scrypt` lebih tepat. Fernet juga memakai AES-128 dalam mode CBC —
  layak untuk demonstrasi, bukan untuk aset bernilai.
- **Proteksi malware / keylogger.** Ini murni masalah di luar kendali kode.
- **Konsensus jaringan.** Ledger di sini adalah file lokal. Siapa pun yang bisa menulis
  `data/ledger.json` bebas menciptakan saldo. Pada blockchain sungguhan, mekanisme
  konsensus yang mencegah hal tersebut.
- **Recovery / lost-seed flow.** Kehilangan seed = kehilangan aset, tanpa jalur pemulihan.

## Praktik yang tetap benar

Meskipun tidak untuk produksi, kode ini mengikuti praktik yang benar dan layak dipelajari:

- RNG dari `os.urandom` / `secrets`, bukan `random`
- PBKDF2 dengan 600.000 iterasi dan salt unik 16 byte per keystore
- Password dibandingkan secara timing-safe
- **Atomic write** (`*.tmp` lalu `os.replace`) supaya keystore tidak pernah setengah tertulis
- **Keystore berversi**, supaya format lama bisa dimigrasi alih-alih rusak
- **Low-S enforcement** pada setiap tanda tangan (anti-malleability)
- **Nonce per pengirim** untuk mencegah replay
- **`chain_id` di dalam payload** untuk domain separation antar jaringan
- Nominal uang memakai **integer minor unit**, bukan `float`
- Tidak ada `print` atau logging yang membocorkan seed phrase / private key

## Yang perlu ditambahkan untuk produksi

Hardening keystore, audit kriptografi independen, perlindungan side-channel, pengujian
fuzzing, dan audit keamanan formal. Semua itu di luar cakupan proyek edukatif ini.