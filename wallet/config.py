# Tujuan File:
# Menyimpan konfigurasi global jaringan simulasi (CHAIN_ID, path penyimpanan data),
# spesifikasi metadata koin (ETH, USDT, BNB) dengan jumlah desimal standar aslinya,
# serta fungsi konversi nominal uang ke/dari integer minor unit (Aturan 12: dilarang
# memakai float untuk nilai uang di seluruh aplikasi).

from __future__ import annotations

import pathlib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext

# --- Parameter Jaringan & Derivasi -------------------------------------------

# ID jaringan simulasi lokal untuk domain separation di dalam payload transaksi
CHAIN_ID: int = 1337

# BIP-44 coin_type standar untuk Ethereum-style address
DEFAULT_COIN_TYPE: int = 60

# --- Lokasi Penyimpanan Data Runtime -----------------------------------------

PROJECT_ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR: pathlib.Path = PROJECT_ROOT / "data"
KEYSTORES_DIR: pathlib.Path = DATA_DIR / "keystores"
INDEX_FILE: pathlib.Path = DATA_DIR / "index.json"
LEDGER_FILE: pathlib.Path = DATA_DIR / "ledger.json"


# --- Spesifikasi Koin --------------------------------------------------------

@dataclass(frozen=True)
class CoinSpec:
    """
    Tujuan: Merepresentasikan metadata koin yang didukung oleh wallet dan ledger.
    - symbol      : kode ticker koin (mis. 'ETH', 'USDT', 'BNB')
    - name        : nama lengkap koin
    - decimals    : jumlah angka desimal minor unit (mis. ETH=18 -> 1 ETH = 10^18 wei)
    - default_fee : biaya transaksi standar dalam satuan integer minor unit
    """

    symbol: str
    name: str
    decimals: int
    default_fee: int

    @property
    def unit_scale(self) -> int:
        """Tujuan: Mengembalikan faktor pengali 1 unit utuh ke minor unit (10^decimals)."""
        return 10**self.decimals


COINS: dict[str, CoinSpec] = {
    "ETH": CoinSpec(
        symbol="ETH",
        name="Ethereum",
        decimals=18,
        default_fee=21_000 * 10**9,  # 0.000021 ETH (21.000 Gwei) dalam wei
    ),
    "USDT": CoinSpec(
        symbol="USDT",
        name="Tether USD",
        decimals=6,
        default_fee=100_000,  # 0.1 USDT dalam minor unit (10^6)
    ),
    "BNB": CoinSpec(
        symbol="BNB",
        name="BNB",
        decimals=18,
        default_fee=10**14,  # 0.0001 BNB dalam minor unit (10^18)
    ),
}


def get_coin(symbol: str) -> CoinSpec:
    """
    Tujuan: Mengambil objek CoinSpec berdasarkan simbol koin (case-insensitive)
    dan menolak simbol koin yang tidak terdaftar.
    """
    if not isinstance(symbol, str):
        raise TypeError(f"symbol harus str, dapat: {type(symbol).__name__}")
    key = symbol.strip().upper()
    if key not in COINS:
        raise ValueError(f"koin tidak didukung: {symbol!r}")
    return COINS[key]


def check_minor_int(name: str, value: int, *, allow_zero: bool = False) -> int:
    """
    Tujuan: Memvalidasi bahwa nilai uang/saldo/fee sudah berupa integer minor unit murni
    (menolak float, bool, dan nilai negatif) sesuai Aturan 12.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} harus int (minor unit), bukan {type(value).__name__}")
    if allow_zero:
        if value < 0:
            raise ValueError(f"{name} harus >= 0, dapat: {value}")
    else:
        if value <= 0:
            raise ValueError(f"{name} harus > 0, dapat: {value}")
    return value


def parse_amount(value: str | int, symbol: str = "ETH", *, allow_zero: bool = False) -> int:
    """
    Tujuan: Mengubah input nominal manusia (str desimal seperti '1.5' atau int unit utuh)
    menjadi integer minor unit sesuai desimal koin tanpa pernah menyentuh tipe float.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TypeError(
            f"nominal harus str atau int (bukan float/bool), dapat: {type(value).__name__}"
        )
    coin = get_coin(symbol)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("nominal tidak boleh kosong")
    else:
        text = str(value)

    # Presisi 78 digit mencakup penuh rentang uint256 tanpa risiko pembulatan
    with localcontext() as ctx:
        ctx.prec = 78
        try:
            d = Decimal(text)
        except InvalidOperation as err:
            raise ValueError(f"format nominal tidak valid: {value!r}") from err

        if not d.is_finite():
            raise ValueError("nominal harus bilangan hingga (finite)")

        scaled = d.scaleb(coin.decimals)
        if scaled != int(scaled):
            raise ValueError(
                f"terlalu banyak angka desimal untuk {coin.symbol} (maks {coin.decimals})"
            )
        minor = int(scaled)

    return check_minor_int("amount", minor, allow_zero=allow_zero)


def format_amount(amount_minor: int, symbol: str = "ETH") -> str:
    """
    Tujuan: Mengubah integer minor unit kembali menjadi string desimal yang rapi
    untuk ditampilkan ke pengguna (misal 1500000000000000000 -> '1.5').
    """
    check_minor_int("amount_minor", amount_minor, allow_zero=True)
    coin = get_coin(symbol)
    with localcontext() as ctx:
        ctx.prec = 78
        d = Decimal(amount_minor).scaleb(-coin.decimals)
        text = format(d, f".{coin.decimals}f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text
