from __future__ import annotations

from decimal import Decimal

from wallet.config import COINS, format_amount
from wallet.crypto.address import shorten
from wallet.pricing import calculate_usd_value, format_usd_price
from wallet.transaction import Transaction
from wallet.ui.console import print_header # , pause


# Menampilkan tabel saldo tiap koin (ETH, USDT, BNB), harga per koin ($... atau N/A), dan estimasi nilai USD ($... atau N/A).
def render_portfolio(
    address: str,
    balances: dict[str, int],
    prices: dict[str, Decimal | None] | None = None,
) -> None:
    safe_prices = prices or {}

    print_header(f"PORTOFOLIO [{shorten(address)}]")
    print(f"{'KOIN':<8} | {'SALDO':>22} | {'HARGA (USD)':>14} | {'ESTIMASI (USD)':>16}")
    print("-" * 69)

    # Iterasi mengikuti daftar koin resmi di COINS (atau gabungan dengan balances)
    symbols = list(COINS.keys()) if COINS else ["ETH", "USDT", "BNB"]

    for sym in symbols:
        minor_balance = balances.get(sym, 0)
        price = safe_prices.get(sym)

        # Format saldo dari integer minor unit ke tampilan desimal
        formatted_bal = format_amount(minor_balance, sym)
        formatted_price = format_usd_price(price)
        formatted_val = calculate_usd_value(minor_balance, sym, price)

        # Tambahkan prefix '$' bila nilainya bukan "N/A" dan belum ber-prefix '$'
        if formatted_price != "N/A" and not formatted_price.startswith("$"):
            formatted_price = f"${formatted_price}"
        if formatted_val != "N/A" and not formatted_val.startswith("$"):
            formatted_val = f"${formatted_val}"

        print(f"{sym:<8} | {formatted_bal:>22} | {formatted_price:>14} | {formatted_val:>16}")

    print("-" * 69)


# Menampilkan daftar riwayat transaksi (KIRIM -> / TERIMA <-, nominal dengan format_amount, fee, nonce, dan tx_id pendek).
def render_history(address: str, history: list[Transaction]) -> None:
    print_header(f"RIWAYAT TRANSAKSI [{shorten(address)}]")
    if not history:
        print("Belum ada riwayat transaksi.")
        return

    my_addr = address.lower()

    for idx, tx in enumerate(history, start=1):
        # Sesuaikan nama atribut sender/receiver dengan class Transaction milikmu
        sender = getattr(tx, "sender", getattr(tx, "sender_address", ""))
        receiver = getattr(tx, "recipient", getattr(tx, "receiver_address", ""))
        coin = getattr(tx, "coin", getattr(tx, "symbol", ""))

        if sender.lower() == my_addr:
            direction = f"KIRIM -> {shorten(receiver)}"
        else:
            direction = f"TERIMA <- {shorten(sender)}"

        amount_str = format_amount(tx.amount, coin)
        fee_str = format_amount(tx.fee, coin)
        short_tx_id = f"{tx.tx_id[:10]}..." if tx.tx_id else "N/A"

        print(
            f"{idx:>2}. [{short_tx_id}] {direction:<24} | "
            f"{amount_str} {coin} (fee: {fee_str}, nonce: {tx.nonce})"
        )


# Menampilkan antrean transaksi pending di mempool.
def render_mempool(pending: list[Transaction]) -> None:
    print_header(f"MEMPOOL (Pending: {len(pending)})")
    if not pending:
        print("Mempool kosong (tidak ada transaksi pending).")
        return

    for idx, tx in enumerate(pending, start=1):
        sender = getattr(tx, "sender", getattr(tx, "sender_address", ""))
        receiver = getattr(tx, "recipient", getattr(tx, "receiver_address", ""))
        coin = getattr(tx, "coin", getattr(tx, "symbol", ""))

        amount_str = format_amount(tx.amount, coin)
        fee_str = format_amount(tx.fee, coin)
        short_tx_id = f"{tx.tx_id[:10]}..." if tx.tx_id else "N/A"

        print(
            f"{idx:>2}. [{short_tx_id}] {shorten(sender)} -> {shorten(receiver)} | "
            f"{amount_str} {coin} (fee: {fee_str}, nonce: {tx.nonce})"
        )