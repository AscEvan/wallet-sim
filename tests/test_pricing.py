"""Test suite untuk wallet.pricing (CoinMarketCap client & fallback N/A)."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from decimal import Decimal

import pytest
from wallet.pricing import calculate_usd_value, fetch_prices, format_usd_price


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_fetch_prices_without_api_key_returns_none(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("API_KEY", raising=False)
    prices = fetch_prices(["ETH", "USDT", "BNB"], api_key="")
    assert prices == {"ETH": None, "USDT": None, "BNB": None}
    assert format_usd_price(None) == "N/A"
    assert calculate_usd_value(10**18, "ETH", None) == "N/A"


def test_fetch_prices_success_and_value_calculation(monkeypatch: pytest.MonkeyPatch):
    payload = {
        "data": {
            "ETH": {"quote": {"USD": {"price": 2500.5}}},
            "USDT": [{"quote": {"USD": {"price": 1.0}}}],
        }
    }

    def fake_urlopen(request, context=None, timeout=None):
        assert request.headers.get("X-cmc_pro_api_key") == "test-key"
        return _FakeResponse(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    prices = fetch_prices(["ETH", "USDT", "BNB"], api_key="test-key")
    assert prices["ETH"] == Decimal("2500.5")
    assert prices["USDT"] == Decimal("1.0")
    assert prices["BNB"] is None
    assert format_usd_price(prices["ETH"]) == "$2,500.50"
    assert calculate_usd_value(2 * 10**18, "ETH", prices["ETH"]) == "$5,001.00"
    assert calculate_usd_value(15_500_000, "USDT", prices["USDT"]) == "$15.50"


def test_fetch_prices_network_error_degrades_gracefully(monkeypatch: pytest.MonkeyPatch):
    def fake_urlopen(request, context=None, timeout=None):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    prices = fetch_prices(["ETH", "USDT"], api_key="test-key")
    assert prices == {"ETH": None, "USDT": None}
