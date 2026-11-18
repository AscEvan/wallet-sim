'''
Menyimpan state buku besar berbasis Account Model
(balances, nonces, history) dalam satuan integer minor
unit (Aturan 12), menerapkan 7 lapis validasi sebelum
mengubah saldo, menyediakan faucet() untuk pengujian,
dan menyimpan state secara atomik ke data/ledger.json.
'''

from __future__ import annotations

import pathlib

from wallet.config import CHAIN_ID, LEDGER_FILE, check_minor_int, get_coin
from wallet.crypto import to_eip55
from wallet.storage import DEFAULT_SCHEMA_VERSION, read_json, write_json_atomic
from wallet.transaction import Transaction, verify_transaction

_DEFAULT_LEDGER_DATA: dict = {
    "version": DEFAULT_SCHEMA_VERSION,
    "balances" : {},
    "nonces": {},
    "history": []
}


class Ledger:
    def __init__(self, *, ledger_file: pathlib.Path | None = LEDGER_FILE, chain_id: int = CHAIN_ID) -> None:
        self.ledger_file = pathlib.Path(ledger_file) if ledger_file is not None else None 
        self.chain_id = check_minor_int("chain_id", chain_id, allow_zero=False)
        self._balances: dict[str, dict[str, int]] = {}
        self._nonces: dict[str, int] = {}
        self._history: list[Transaction] = []
        self._seen_tx_ids: set[str] = set()

        if self.ledger_file is not None :
            self.load()
        
    
    def load(self) -> None:
        if self.ledger_file is None:
            return 
        
        data = read_json(self.ledger_file, default=_DEFAULT_LEDGER_DATA)
        self._balances = {
            to_eip55(addr) : {
                get_coin(coin).symbol: check_minor_int("balance", bal, allow_zero=True)
                for coin, bal in coins.items()
            }
            for addr, coins in data.get("balances", {}).items()
        }
        self._nonces = {
            to_eip55(addr): check_minor_int("nonce", n, allow_zero=True)
            for addr, n in data.get('nonces', {}).items()
        }
        self._history = [Transaction.from_dict(item) for item in data.get('history', [])]
        self._seen_tx_ids = {tx.tx_id for tx in self._history}

    def save(self) -> None:
        if self.ledger_file is None:
            return 

        data = {
            "version": DEFAULT_SCHEMA_VERSION,
            "balances" : self._balances,
            "nonces" : self._nonces,
            "history": [tx.to_dict() for tx in self._history]
        }    

        write_json_atomic(self.ledger_file, data)
    
    def get_balance(self, address: str, coin: str = "ETH") -> int:
        addr = to_eip55(address)
        sym = get_coin(coin).symbol
        return self._balances.get(addr, {}).get(sym, 0)
    
    def get_all_balances(self, address: str) -> dict[str, int]:
        addr = to_eip55(address)
        return dict(self._balances.get(addr, {}))
    
    def get_nonce(self, address: str) -> int:
        addr = to_eip55(address)
        return self._nonces.get(addr, 0)
    
    def get_history(self, address: str | None = None) -> list[Transaction]:
        if address is None:
            return list(self._history)
        addr = to_eip55(address)
        return [
            tx for tx in self._history
            if tx.sender == addr or tx.recipient == addr
        ]

    '''Tambah saldo awal untuk gensis'''
    def faucet(self, address: str, coin: str, amount: int) -> int:
        addr = to_eip55(address)
        sym = get_coin(coin).symbol
        check_minor_int('amount', amount, allow_zero=False)
        new_balance = self.get_balance(addr, sym) + amount
        self._balances.setdefault(addr, {})[sym] = new_balance
        self.save()
        return new_balance
    
    def apply(self, tx: Transaction) -> tuple[bool, str]:
        ok, reason = verify_transaction(tx, expected_chain_id=self.chain_id)
        if not ok:
            return (False, reason)
        
        coin_spec = get_coin(tx.coin)
        if tx.fee < coin_spec.default_fee:
            return (False, f"fee kurang dari minimum ({coin_spec.default_fee})")
        if tx.tx_id in self._seen_tx_ids:
            return (False, "tx_id sudah pernah diproses")
        
        # validasi nonce
        expected_nonce = self.get_nonce(tx.sender)
        if tx.nonce != expected_nonce:
            return (False, f"nonce tidak cocok, diharapkan : {expected_nonce}, dapat: {tx.nonce}")
        
        # validasi saldo
        total_cost = tx.amount + tx.fee
        sender_balance = self.get_balance(tx.sender, tx.coin)
        if sender_balance < total_cost:
            return (False, f"saldo {tx.coin} tidak cukuo: punya {sender_balance}, butuh: {total_cost}")

        # set
        self._balances.setdefault(tx.sender, {})[tx.coin] = sender_balance - total_cost
        self._balances.setdefault(tx.recipient, {})[tx.coin] = self.get_balance(tx.recipient, tx.coin) + tx.amount
        self._nonces[tx.sender] = expected_nonce + 1
        self._history.append(tx)
        self._seen_tx_ids.add(tx.tx_id)
        self.save()
        return (True, 'OK')

    

