'''
Tujuan Utama Modul transaction.py
  1. Menyusun payload transaksi kanonik (JSON
  terurut tanpa spasi) yang mencakup chain_id
  (domain separation) dan nonce (anti-replay),
  dengan nominal amount & fee berupa integer minor
  unit (Aturan 12).
  2. Menandatangani transaksi dengan PrivateKey.
  sign(message_hash(payload_bytes)) dan mengikat
  tx_id = sha256(payload_bytes + signature_bytes).
  3. Memverifikasi transaksi secara menyeluruh
  (verify_transaction), termasuk memastikan
  public_key pengirim benar-benar menghasilkan
  alamat sender (anti-spoofing).
'''

from __future__ import annotations

import hashlib
import json 
import time
from dataclasses import asdict, dataclass

from wallet.config import CHAIN_ID, check_minor_int, get_coin
from wallet.crypto import (
    PrivateKey,
    PublicKey,
    is_checksum_valid,
    message_hash,
    public_key_to_address,
    to_eip55
)

'''
mengubah dict payload transaction menjadi bytes json kanonik (urut abjad)
'''
def canonical_payload_bytes(payload: dict) -> bytes:
    if not isinstance(payload, dict):
        raise TypeError(f'payload harus dict, dapat: {type(payload)}')
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

@dataclass(frozen=True)
class Transaction:
    chain_id: int
    sender: str          # Alamat EIP-55 pengirim
    recipient: str       # Alamat EIP-55 penerima
    coin: str            # Simbol koin ('ETH', 'USDT', 'BNB')
    amount: int          # Nominal integer minor unit (> 0)
    fee: int             # Biaya integer minor unit (>= 0)
    nonce: int           # Nomor urut transaksi pengirim (>= 0)
    timestamp: int       # Unix timestamp integer dalam detik (> 0)
    memo: str            # Catatan opsional
    public_key_hex: str  # Public key pengirim (hex)
    signature_hex: str   # Signature DER low-S (hex)
    tx_id: str           # SHA-256 hex dari (payload_bytes + signature_bytes

    '''mengambil 9 field inti yang di sign oleh sender'''
    def payload_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "coin": self.coin,
            "amount": self.amount,
            "fee": self.fee,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "memo": self.memo,
        }

    '''mengembalikan byte canonical JSON dari payload_dict'''
    def payload_bytes(self) -> bytes:
        return canonical_payload_bytes(self.payload_dict())

    '''mengembalikan digest sha256 (32 bytes) atas payload_bytes'''
    def payload_digest(self) -> bytes:
        return message_hash(self.payload_bytes())

    '''shortcut boolean untuk cek keabsahan kriptografis transaksi'''
    def is_valid(self, *, expected_chain_id : int = CHAIN_ID):
        ok, _ = verify_transaction(self, expected_chain_id=expected_chain_id)
        return ok 

    '''mengubah objek Transactioin menjadi dict untuk simpan ke JSON'''
    def to_dict(self) -> dict:
        return asdict(self)

    
    '''merekontruksi objek Transaction dari dict JSON'''
    @classmethod
    def from_dict(cls, data: dict) -> Transaction:
        if not isinstance(data, dict):
            raise TypeError(f'data harus dict, dapat: {type(data)}')

        try:
            return cls(
                chain_id=data["chain_id"],
                sender=data["sender"],
                recipient=data["recipient"],
                coin=data["coin"],
                amount=data["amount"],
                fee=data["fee"],
                nonce=data["nonce"],
                timestamp=data["timestamp"],
                memo=data.get("memo", ""),
                public_key_hex=data["public_key_hex"],
                signature_hex=data["signature_hex"],
                tx_id=data["tx_id"],
            )
        except KeyError as err:
            raise ValueError(f'field transaksi tidak lengkap: {err}') from err


'''membangun dan sign transaksi baru menggunakan PrivateKey pengirim'''
def create_signed_transaction(
        private_key: PrivateKey,
        recipient: str, 
        coin: str,
        amount: int, 
        nonce: int,
        *, 
        fee: int | None = None,
        memo: str = "",
        chain_id: int = CHAIN_ID,
        timestamp: int | None = None
    ) -> Transaction:
    
    if not isinstance(private_key, PrivateKey):
        raise TypeError(f'private_key harus bentuk PrivateKey, dapat: {type(private_key)}')
    
    sender_addr = public_key_to_address(private_key.public_key)
    pub_hex = private_key.public_bytes(compressed=True).hex()
    recipient_addr = to_eip55(recipient)

    if sender_addr == recipient_addr:
        raise ValueError(f'tidak bisa mengirim ke alamat sendiri')
    
    coin_spec = get_coin(coin)

    # validasi integer minor unit
    amount = check_minor_int("amount", amount, allow_zero=False)
    actual_fee = (
        coin_spec.default_fee
        if fee is None
        else check_minor_int("fee", fee, allow_zero=True)
    )
    nonce = check_minor_int("nonce", nonce, allow_zero=True)
    chain_id = check_minor_int("chain_id", chain_id, allow_zero=False)
    actual_ts = (
        int(time.time())
        if timestamp is None
        else check_minor_int("timestamp", timestamp, allow_zero=False)
    )

    if not isinstance(memo, str):
        raise TypeError(f'memo harus bentuk str, dapat: {type(memo)}')

    payload = {
        "chain_id": chain_id,
        "sender": sender_addr,
        "recipient": recipient_addr,
        "coin": coin_spec.symbol,
        "amount": amount,
        "fee": actual_fee,
        "nonce": nonce,
        "timestamp": actual_ts,
        "memo": memo,
    }
    raw_payload = canonical_payload_bytes(payload)
    digest = message_hash(raw_payload)
    sig_bytes = private_key.sign(digest)
    tx_id = hashlib.sha256(raw_payload + sig_bytes).hexdigest()

    return Transaction(
        chain_id=chain_id,
        sender=sender_addr,
        recipient=recipient_addr,
        coin=coin_spec.symbol,
        amount=amount,
        fee=actual_fee,
        nonce=nonce,
        timestamp=actual_ts,
        memo=memo,
        public_key_hex=pub_hex,
        signature_hex=sig_bytes.hex(),
        tx_id=tx_id,
    )


'''memeriksa keabsahan struktur dan signing tanpa menyentuh saldo ledger'''
def verify_transaction(tx: Transaction, *, expected_chain_id: int = CHAIN_ID) -> tuple[bool, str]: #
    if not isinstance(tx, Transaction):
        raise ValueError(f'tx harus bentuk Transaction, dapat: {type(tx)}')
    
    try:
        check_minor_int("chain_id", tx.chain_id, allow_zero=False)
        check_minor_int("amount", tx.amount, allow_zero=False)
        check_minor_int("fee", tx.fee, allow_zero=True)
        check_minor_int("nonce", tx.nonce, allow_zero=True)
        check_minor_int("timestamp", tx.timestamp, allow_zero=False)
        coin_spec = get_coin(tx.coin)
    except (TypeError, ValueError) as err:
        return (False, str(err))
    if tx.coin != coin_spec.symbol or not isinstance(tx.memo, str):
        return (False, "coin atau memo tidak valid")

    # domain separation
    if tx.chain_id != expected_chain_id:
        return (False, "chain_id tidak cocok")
    
    if not is_checksum_valid(tx.sender) or not is_checksum_valid(tx.recipient):
            return (False, "alamat sender atau recipient bukan EIP-55 yang valid")
    if tx.sender == tx.recipient:
        return (False, "sender tidak boleh sama dengan recipient")
    
    # anti spoofing
    try:
        pub = PublicKey.from_bytes(bytes.fromhex(tx.public_key_hex))
        sig_bytes = bytes.fromhex(tx.signature_hex)
    except ValueError:
        return ValueError(f'hex/pubkey rusak')
    
    if public_key_to_address(pub) != tx.sender:
        return (False, "public_key tidak cocok dengan sender")

    # verify signature ECDSA low-S
    sig_bytes = bytes.fromhex(tx.signature_hex)
    if not pub.verify(sig_bytes, tx.payload_digest()):
        return (False, "signature tidak valid")

    # verify tx_id
    expected_id = hashlib.sha256(tx.payload_bytes() + sig_bytes).hexdigest()
    if tx.tx_id != expected_id:
        return (False, "tx_id tidak cocok")
    return (True, 'OK')


