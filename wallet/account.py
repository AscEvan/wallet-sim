from __future__ import annotations

import pathlib
import time

from wallet.config import (
    CHAIN_ID,
    DEFAULT_COIN_TYPE,
    INDEX_FILE,
    KEYSTORES_DIR,
)
from wallet.crypto import (
    KDF_ITERATIONS,
    STRENGTH_12,
    PrivateKey,
    PublicKey,
    build_path,
    decrypt_secret,
    derive_private_key,
    encrypt_secret,
    generate,
    load_keystore,
    public_key_to_address,
    save_keystore,
    to_eip55,
    to_seed,
)

from wallet.storage import DEFAULT_SCHEMA_VERSION, read_json, write_json_atomic
from wallet.transaction import Transaction, create_signed_transaction

_DEFAULT_INDEX_DATA: dict = {
    "version": DEFAULT_SCHEMA_VERSION,
    "accounts": {},
}


class Wallet:
    def __init__(self, private_key: PrivateKey, *, label: str = "", account_index: int = 0 ) -> None:
        if not isinstance(private_key, PrivateKey):
            raise TypeError(f'private_key harus bentuk PrivateKey, dapat: {type(private_key)}')
        if not isinstance(label, str):
            raise TypeError(f'label harus bentuk str, dapat: {type(label)}')
        if not isinstance(account_index, int) or account_index < 0:
            raise ValueError(f'account_index harus bertipe int dan >=0, dapat: {type(account_index)}')
        
        self._private_key = private_key
        self.address: str = public_key_to_address(private_key.public_key)
        self.label: str = label
        self.account_index: int = account_index

    def __repr__(self) -> str:
        return f'<Wallet address={self.address} label={self.label!r}>'

    @property
    def public_key(self) -> PublicKey:
        return self._private_key.public_key
    

    '''Menurunkan Wallet dari seed phrase BIP-39
        dan path BIP-32 (m/44'/60'/account'/0/index)'''
    @classmethod
    def from_mnemonic(cls,
                    phrase: str,
                    passphrase: str="",
                    *,
                    account: int = 0,
                    index: int = 0, 
                    coin_type: int = DEFAULT_COIN_TYPE,
                    label: str = "" ) -> Wallet:
        seed = to_seed(phrase, passphrase)
        path = build_path(account, index, coin_type) 
        raw_priv = derive_private_key(seed, path)
        
        return cls(PrivateKey.from_bytes(raw_priv), label=label, account_index=index)

    @classmethod
    def from_private_key(
        cls,
        private_key_input: str | bytes,
        *, 
        label: str = "" ) -> Wallet:
        if isinstance(private_key_input, (bytes, bytearray)):
            priv = PrivateKey.from_bytes(private_key_input)
        elif isinstance(private_key_input, str):
            priv = PrivateKey.from_hex(private_key_input.strip())
        else:
            raise TypeError(f"private key harus bentuk bytes / str, dapat: {type(private_key_input)}")
        
        return cls(priv, label=label, account_index=0)



    ''' Menghasilkan mnemonic baru (12 atau 24
        kata), membuat objek Wallet, dan mengembalikan
        tuple (wallet, phrase)''' 
    @classmethod
    def create_new(cls, *,
                strength: int = STRENGTH_12, 
                passphrase: str = "", 
                account: int = 0, 
                index: int = 0, 
                label: str = "") -> tuple[Wallet, str] :
        phrase = generate(strength)
        wallet = cls.from_mnemonic(phrase, passphrase, account=account, index=index, label=label)

        return wallet, phrase


    '''enkripsi kunci privat dompet ke
        <keystores_dir>/<address>.json dan mencatat akun
        di index.json.'''
    def save(self, password: str, *, keystore_dir: pathlib.Path = KEYSTORES_DIR, index_file = INDEX_FILE, iterations: int = KDF_ITERATIONS) -> pathlib.Path:
        ks_data = encrypt_secret(self._private_key.to_bytes(), password, self.address, iterations=iterations)
        ks_path = pathlib.Path(keystore_dir) / f"{self.address}.json"
        save_keystore(ks_data, ks_path) 

        index_data = read_json(index_file, default=_DEFAULT_INDEX_DATA)
        index_data["accounts"][self.address] = {
            "address" : self.address,
            "label" : self.label,
            "account_index" : self.account_index,
            "keystore_file" : ks_path.name,
            "created_at" : int(time.time())
        }

        write_json_atomic(index_file, index_data)
        return ks_path 


    '''Membuka dompet dari file keystore di disk
        menggunakan password.'''
    @classmethod
    def unlock(cls,
                address:str,
                password: str, 
                *, 
                keystore_dir: pathlib.Path = KEYSTORES_DIR,
                index_file: pathlib.Path = INDEX_FILE) -> Wallet:
        checksudm_addr = to_eip55(address)
        ks_path = pathlib.Path(keystore_dir) / f"{checksudm_addr}.json"
        ks_data = load_keystore(ks_path)
        raw_priv = decrypt_secret(ks_data, password)
        meta = read_json(index_file, default=_DEFAULT_INDEX_DATA)["accounts"].get(checksudm_addr, {})
        wallet = cls(PrivateKey.from_bytes(raw_priv), label=meta.get("label", ""), account_index=meta.get("account_index", 0))
        
        return wallet


    '''shortcut di objek Wallet untuk membuat
        dan menandatangani transaksi.'''
    def create_transaction(self,
                        recipient: str,
                        coin: str,
                        amount: int, 
                        nonce: int,
                        *,
                        fee: int | None = None,
                        memo: str = "",
                        chain_id: int = CHAIN_ID,
                        timestamp: int | None = None) -> Transaction:
        
        return create_signed_transaction(self._private_key, recipient, coin, amount, nonce, fee=fee, memo=memo, chain_id=chain_id, timestamp=timestamp)
    


def list_accounts(*, index_file: pathlib.Path = INDEX_FILE) -> list[dict]:
    data = read_json(index_file, default=_DEFAULT_INDEX_DATA)
    return list(data["accounts"].values())

