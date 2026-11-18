from __future__ import annotations

import pathlib

from wallet.config import CHAIN_ID, LEDGER_FILE
from wallet.ledger.ledger import Ledger
from wallet.ledger.mempool import Mempool
from wallet.transaction import Transaction


'''facade jaringan lokal antara mempool dan ledger'''
class Node:
    def __init__(self, *,
                ledger: Ledger | None = None,
                mempool: Mempool | None = None,
                ledger_file: pathlib.Path | None =
                LEDGER_FILE,
                chain_id: int = CHAIN_ID ) -> None:
        self.ledger: Ledger = (
            ledger if ledger is not None else
            Ledger(ledger_file=ledger_file,
            chain_id=chain_id)
        )
        self.mempool: Mempool = (
            mempool if mempool is not None else
            Mempool(chain_id=self.ledger.chain_id)
        )
    
    def submit(self, tx: Transaction) -> tuple[bool, str]:
        if not isinstance(tx, Transaction):
            return (False, f"tx harus Transaction, dapat: {type(tx).__name__}")
        if any(h.tx_id == tx.tx_id for h in self.ledger.get_history()):
            return (False, "tx_id sudah pernah dikonfirmasi di ledger")
        return self.mempool.submit(tx)

    '''memasukkan proses antrean mempool dan menerapkan ke state ledger'''
    def commit(self, max_count: int | None = None) -> list[tuple[Transaction, bool, str]]:
            batch = self.mempool.pop_batch(max_count)
            results: list[tuple[Transaction, bool, str]] = []
            for tx in batch:
                ok, reason = self.ledger.apply(tx)
                results.append((tx, ok, reason))
            return results

    def get_balance(self, address: str, coin: str = "ETH") -> int:
            return self.ledger.get_balance(address, coin)

    def get_all_balances(self, address: str) -> dict[str, int]:
        return self.ledger.get_all_balances(address)

    def get_history(self, address: str | None = None) -> list[Transaction]:
        return self.ledger.get_history(address)

    def faucet(self, address: str, coin: str, amount: int) -> int:
        return self.ledger.faucet(address, coin, amount)
    
    def get_nonce(self, address: str) -> int:
        return self.ledger.get_nonce(address)

