'''
Menampung antrean transaksi pending
  (collections.deque) dan melakukan validasi awal tanpa-
  ledger (cek duplikat, struktur, alamat EIP-55,
  chain_id, public_key, dan signature low-S) sebelum
  transaksi di-commit ke Ledger.
'''

from __future__ import annotations

from collections import deque

from wallet.config import CHAIN_ID, check_minor_int, get_coin
from wallet.transaction import Transaction, verify_transaction


class Mempool:
    '''antrean transaksi di pending sebelum dieksekusi ke ledger'''

    def __init__(self, *, chain_id: int = CHAIN_ID) -> None:
        self.chain_id: int = check_minor_int("chain_id", chain_id, allow_zero=False)
        self._queue: deque[Transaction] = deque()
        self._pending_ids: set[str] = set()

    '''memvalidasi transaksi secara kriptografis dan memasukkan ke antrean'''
    def submit(self, tx: Transaction) -> tuple[bool, str]:
        if not isinstance(tx, Transaction):
            return (False, f"tx harus Transaction, dapat: {type(tx)}")
        if tx.tx_id in self._pending_ids:
            return (False, "tx_id sudah ada di mempool")

        ok, reason = verify_transaction(tx, expected_chain_id=self.chain_id)
        if not ok:
            return (False, reason)
        
        coin_spec = get_coin(tx.coin)
        if tx.fee < coin_spec.default_fee:
            return (False, f"fee kurang dari minimum ({coin_spec.default_fee})")

        self._queue.append(tx)
        self._pending_ids.add(tx.tx_id)

        return (True, "OK")


    '''mengeluarkan sejumlah transaksi dari depan antrean untuk diproses Node'''
    def pop_batch(self, max_count: int | None = None) -> list[Transaction]:
        if max_count is None:
            count = len(self._queue)
        else:
            count = min(check_minor_int("max_count",
            max_count, allow_zero=False),
            len(self._queue))
        
        batch: list[Transaction] = []
        for _ in range(count):
            tx = self._queue.popleft()
            self._pending_ids.discard(tx.tx_id)
            batch.append(tx)
        return batch
    

    '''melihat daftar transaksi pending'''
    def peek(self) -> list[Transaction]:
        return list(self._queue)
    
    '''mengosongkan seluruh antrean mempool'''
    def clear(self) -> None:
        self._queue.clear()
        self._pending_ids.clear()
    
    def __len__(self) -> int:
        return len(self._queue)


