"""Test suite Fase 2: config, storage, transaction, account, dan ledger/node."""

from __future__ import annotations

from dataclasses import replace
import pathlib

import pytest
from wallet.account import Wallet, list_accounts
from wallet.config import format_amount, get_coin, parse_amount
from wallet.ledger import Ledger, Mempool, Node
from wallet.storage import StorageError, read_json, write_json_atomic
from wallet.transaction import Transaction, verify_transaction


def test_config_minor_unit_conversion_and_float_rejection():
    eth_minor = parse_amount("1.5", "ETH")
    assert eth_minor == 1_500_000_000_000_000_000
    assert format_amount(eth_minor, "ETH") == "1.5"

    usdt_minor = parse_amount("25.123456", "USDT")
    assert usdt_minor == 25_123_456
    assert format_amount(usdt_minor, "USDT") == "25.123456"

    # Aturan 12: float dan bool wajib ditolak
    with pytest.raises(TypeError):
        parse_amount(1.5, "ETH")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        parse_amount(True, "ETH")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        parse_amount("1.1234567", "USDT")  # lebih dari 6 desimal


def test_storage_atomic_and_versioning(tmp_path: pathlib.Path):
    target = tmp_path / "data" / "state.json"
    default_doc = {"version": 1, "items": []}
    assert read_json(target, default=default_doc) == default_doc

    saved_doc = {"version": 1, "items": ["a", "b"]}
    write_json_atomic(target, saved_doc)
    assert target.exists()
    assert list(target.parent.glob("*.tmp")) == []
    assert read_json(target) == saved_doc

    with pytest.raises(StorageError):
        write_json_atomic(target, {"version": 2})


def test_wallet_account_and_transaction_security(tmp_path: pathlib.Path):
    alice, phrase = Wallet.create_new(label="Alice")
    bob, _ = Wallet.create_new(label="Bob")
    assert phrase not in repr(alice)

    ks_dir = tmp_path / "keystores"
    idx_file = tmp_path / "index.json"
    alice.save("AlicePass123", keystore_dir=ks_dir, index_file=idx_file, iterations=2_000)

    accounts = list_accounts(index_file=idx_file)
    assert len(accounts) == 1
    assert accounts[0]["address"] == alice.address

    unlocked = Wallet.unlock(alice.address, "AlicePass123", keystore_dir=ks_dir, index_file=idx_file)
    tx = unlocked.create_transaction(
        bob.address,
        "ETH",
        parse_amount("2", "ETH"),
        nonce=0,
        memo="pembayaran",
    )
    assert tx.is_valid() is True
    assert Transaction.from_dict(tx.to_dict()) == tx

    # Spoofing public key
    spoofed = replace(tx, public_key_hex=bob.public_key.to_bytes(compressed=True).hex())
    ok, reason = verify_transaction(spoofed)
    assert ok is False
    assert "public_key" in reason


def test_node_mempool_and_ledger_end_to_end(tmp_path: pathlib.Path):
    alice, _ = Wallet.create_new(label="Alice")
    bob, _ = Wallet.create_new(label="Bob")

    lf = tmp_path / "ledger.json"
    node = Node(ledger=Ledger(ledger_file=lf), mempool=Mempool())

    initial = parse_amount("10", "ETH")
    node.faucet(alice.address, "ETH", initial)
    assert node.get_balance(alice.address, "ETH") == initial

    send_amt = parse_amount("3", "ETH")
    tx = alice.create_transaction(bob.address, "ETH", send_amt, nonce=0)
    ok_sub, _ = node.submit(tx)
    assert ok_sub is True

    # Duplikat di mempool ditolak
    ok_dup, _ = node.submit(tx)
    assert ok_dup is False

    results = node.commit()
    assert len(results) == 1
    _, ok_commit, msg_commit = results[0]
    assert ok_commit is True and msg_commit == "OK"

    fee = get_coin("ETH").default_fee
    assert node.get_balance(alice.address, "ETH") == initial - send_amt - fee
    assert node.get_balance(bob.address, "ETH") == send_amt
    assert len(node.get_history(alice.address)) == 1
