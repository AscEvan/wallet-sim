from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

from decimal import Decimal, InvalidOperation, localcontext
from wallet.config import check_minor_int, get_coin
from dotenv import find_dotenv, load_dotenv

CMC_QUOTES_URL = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
DEFAULT_TIMEOUT = 5.0


def get_api_key() -> str | None:
    load_dotenv(find_dotenv())
    key = os.getenv("API_KEY")
    return key.strip() if key and key.strip() else None


def fetch_prices(
    symbols: list[str] | tuple[str, ...] = ("ETH", "USDT", "BNB"),
    *,
    api_key: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Decimal | None]:
    result: dict[str, Decimal | None] = {sym.upper(): None for sym in symbols if sym}
    if not result:
        return {}

    key = api_key if api_key is not None else get_api_key()
    if not key:
        return result  

    try:
        params = urllib.parse.urlencode(
            {
                "symbol": ",".join(result.keys()),
                "convert": "USD",
            }
        )
        request = urllib.request.Request(
            f"{CMC_QUOTES_URL}?{params}", 
            headers={
                "Accept": "application/json",
                "X-CMC_PRO_API_KEY": key,
            },
        )
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            data = response.read()

        api_response = json.loads(data)
        live_data = api_response.get("data", {})

        for sym in result:
            coin_entry = live_data.get(sym)
            # Pada CMC API, entry bisa berupa list (jika simbol duplikat) atau dict
            if isinstance(coin_entry, list) and coin_entry:
                coin_entry = coin_entry[0]
            if isinstance(coin_entry, dict):
                raw_price = (
                    coin_entry.get("quote", {})
                    .get("USD", {})
                    .get("price")
                )
                if raw_price is not None:
                    result[sym] = Decimal(str(raw_price))

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        KeyError,
        ValueError,
        TypeError,
        InvalidOperation,
    ):
    
        return result

    return result


def format_usd_price(price: Decimal | None) -> str:
    if price is None:
        return "N/A"
    return f"${price:,.2f}"  # Atau f"{price:.2f}" sesuai kontrak test lokalmu


def calculate_usd_value(
    amount_minor: int,
    coin_or_decimals: str | int,  # Atau ambil dari config COINS[symbol]["decimals"]
    price: Decimal | None,
) -> str:
    check_minor_int("amount_minor", amount_minor, allow_zero=True)
    decimals = (
        get_coin(coin_or_decimals).decimals
        if isinstance(coin_or_decimals, str) else check_minor_int("decimals", coin_or_decimals, allow_zero=True)
    )

    if price is None:
        return "N/A"
    with localcontext() as ctx:
        ctx.prec = 78
        # Panggil .scaleb() pada objek Decimal, bukan int
        major_amount = Decimal(amount_minor).scaleb(-decimals)
        value = major_amount * price
    return format_usd_price(value)


