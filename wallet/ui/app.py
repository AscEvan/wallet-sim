from __future__ import annotations

from wallet.crypto.bip39 import validate
from wallet.crypto.address import shorten
from wallet.crypto.keystore import InvalidPasswordError, KeystoreError
from wallet.config import COINS, format_amount, get_coin, parse_amount
from wallet.account import Wallet, list_accounts
from wallet.ui.console import clear_screen, pause, prompt, prompt_password, print_header
from wallet.ui.views import render_history, render_mempool, render_portfolio
from wallet.pricing import fetch_prices
from wallet.ledger.node import Node


def _handle_create_wallet() -> Wallet | None:
    clear_screen()
    print_header("BUAT WALLET BARU")
    try:
        raw_strength = prompt("12 / 24 seed")
        if raw_strength is None:
            return None
        strength_str = str(raw_strength).strip()
        if not strength_str or strength_str == "12":
            strength = 128
        elif strength_str == "24":
            strength = 256
        else:
            raise ValueError("Seed Phrases harus 12 / 24 !")
    except ValueError:
        print("Seed Phrases harus 12 / 24 !")
        pause()
        return None

    passphrase = str(prompt("Passphrase (opsional)") or "")
    label = str(prompt("Label (opsional)") or "")
    password = prompt_password()
    if not password:
        print("\nPassword tidak boleh kosong!")
        pause()
        return None

    wallet, phrase = Wallet.create_new(
        strength=strength,
        passphrase=passphrase,
        label=label,
    )
    clear_screen()
    print_header("SIMPAN SEED PHRASE")
    print(f"Seed Phrases ( JAGA BAIK-BAIK ): {phrase}\n")
    pause()
    clear_screen()
    wallet.save(password)
    return wallet


def _handle_import_wallet() -> Wallet | None:
    clear_screen()
    print_header("IMPORT WALLET")
    wallet = None

    try:
        import_from = prompt("1. Seed Phrases\n2. Private Key")

        match(import_from):
            case "1":
                clear_screen()
                print_header("IMPORT SEED PHRASE")
                phrases = str(prompt("Seed Phrases") or "")
                passphrase = str(prompt("Passphrase (opsional)") or "")
                if not validate(phrases):
                    raise TypeError
            case "2":
                clear_screen()
                print_header("IMPORT PRIVATE KEY")
                private_key = str(prompt("Private Key") or "").strip()
                if not private_key:
                    raise TypeError
            case _: raise ValueError

        label = str(prompt("Label") or "")
        password = prompt_password()
        if not password:
            print("\nPassword tidak boleh kosong!")
            pause()
            return None

        if import_from == "1": wallet = Wallet.from_mnemonic(phrases, passphrase, label=label)
        if import_from == "2": wallet = Wallet.from_private_key(private_key, label=label)
        existing_addresses = {acc["address"] for acc in list_accounts()}
        if wallet.address in existing_addresses:
            print(
                f"\nWallet {shorten(wallet.address)} sudah terdaftar! "
                "Silakan gunakan menu Unlock Wallet."
            )
            pause()
            return None

        wallet.save(password)
        clear_screen()
        return wallet
    except TypeError:
        print("\nSeed Phrases atau Password Tidak valid!")
        pause()
        return None
    except KeystoreError as err:
        print(f"\nGagal menyimpan keystore: {err}")
        pause()
        return None
    except ValueError:
        print('\nInvalid Input!')
        pause()
        return None





def _handle_unlock_wallet() -> Wallet | None:
    clear_screen()
    print_header("BUKA WALLET")
    accounts = list_accounts()
    if not accounts:
        print("Tidak ada list address untuk sekarang")
        pause()
        return None

    for i, data in enumerate(accounts, start=1):
        label = data.get("label", "")
        label_info = f" ({label})" if label else ""
        print(f"{i}. {shorten(data['address'])}{label_info}")

    try:
        raw_no = prompt("Address no")
        if raw_no is None:
            return None
        idx = int(str(raw_no).strip())
        if not (1 <= idx <= len(accounts)):
            raise IndexError
        account_info = accounts[idx - 1]
        address = account_info["address"]
        label = account_info.get("label", "")
    except (ValueError, IndexError):
        print(f"\nNomor akun tidak valid! Pilih 1-{len(accounts)}.")
        pause()
        return None

    clear_screen()
    sep = "=" * 30
    label_suffix = f"\t{label}" if label else ""
    print(f"\n{sep}\nADDRESS : {shorten(address)}{label_suffix}\n{sep}")

    password = prompt_password()
    if not password:
        print("\nPassword tidak boleh kosong!")
        pause()
        return None

    try:
        wallet = Wallet.unlock(address, password)
        clear_screen()
        return wallet
    except InvalidPasswordError:
        print("\nPassword salah!")
        pause()
        return None
    except (KeystoreError, FileNotFoundError, ValueError) as err:
        print(f"\nGagal membuka wallet: {err}")
        pause()
        return None


# loop menu aktif setelah login
def _wallet_session(wallet: Wallet, node: Node) -> None:
    while True:
        clear_screen()
        label_str = str(f"{wallet.label}") if wallet.label else ""
        print_header(f"DOMPET AKTIF: {shorten(wallet.address)} {label_str}")
        
        print(f"Address Lengkap: {wallet.address}")
        print(f"Nonce Saat Ini: {node.get_nonce(wallet.address)}")
        print(f"Mempool Pending: {len(node.mempool)} transaksi\n")

        menus = [
            "Portofolio & Harga Koin",
            "Kirim Koin (Buat Transaksi)",
            "Lihat & Proses Mempool (Commit)",
            "Faucet (Tambah Saldo Simulasi)",
            "Riwayat Transaksi",
            "Logout"
        ]
        for i, item in enumerate(menus, start=1):
            print(f"{i}.  {item}")
        
        choice = (prompt("\nPilih menu") or "").strip()
        match choice:
            case "1":
                clear_screen()
                balances = node.get_all_balances(wallet.address)
                prices  = fetch_prices(list(COINS.keys()))
                render_portfolio(wallet.address, balances, prices)
                pause()

            case "2":
                clear_screen()
                print_header("KIRIM KOIN")
                recipient = (prompt("Alamat Tujuan (0x..)") or "").strip()
                coin = (prompt(f"Koin ({'/'.join(COINS.keys())})") or "ETH").strip().upper()
                raw_amount = (prompt("Jumlah dikirim") or "").strip()
                memo = (prompt("Memo (opsional)") or "").strip()
                try:
                    amount_minor = parse_amount(raw_amount, coin)
                    nonce = node.get_nonce(wallet.address)
                    tx = wallet.create_transaction(
                        recipient,
                        coin,
                        amount_minor,
                        nonce,
                        memo=memo)
                    ok, msg = node.submit(tx)
                    if ok:
                        print(f"\n[OK] Transaksi masuk mempool! tx_id: {tx.tx_id[:12]}")
                    else:
                        print(f"\n[DITOLAK] {msg}")
                except (ValueError, TypeError) as err:
                    print(f"\n[ERROR] Input transaksi tidak valid {err}")
                pause()

            case "3":
                clear_screen()
                pending = node.mempool.peek()
                render_mempool(pending)
                if pending:
                    confirm = (prompt("\nProses (commit) semua ke Ledger (y/n)") or "").strip().lower()
                    if confirm == 'y':
                        results = node.commit()
                        for tx, ok, reason in results:
                            status = "Berhasil" if ok else f"GAGAL ({reason})"
                            print(f"- [{tx.tx_id[:10]}...] {status}")
                pause()
            
            case "4":
                clear_screen()
                print_header("FAUCET")
                coin = (prompt(f"Koin Faucet ({'/'.join(COINS.keys())})") or "ETH").strip().upper()
                raw_amount = (prompt("Jumlah Faucet") or "").strip()
                try:
                    amount_minor = parse_amount(raw_amount, coin)
                    new_bal = node.faucet(wallet.address, coin, amount_minor)
                    print(
                        f"\n[OK] Saldo {get_coin(coin).symbol} sekarang: {format_amount(new_bal, coin)} {get_coin(coin).symbol}"
                    )
                except (ValueError, TypeError) as err:
                    print(f"\n[ERROR] Faucet gagal: {err}")
                pause()

            case "5":
                clear_screen()
                render_history(wallet.address, node.get_history(wallet.address))
                pause()
            
            case "6" | "0":
                clear_screen()
                print("\nLogout dari wallet...")
                return
            
            case _:
                print("\nPilihan tidak valid")
                pause()





def main() -> None:
    node = Node()

    while True:
        clear_screen()
        print_header("WALLET SIM")
        active_access_menu = [
            "Buat wallet baru",
            "Buka wallet tersimpan (Keystore)",
            "Import wallet (Seed Phrase / Private Key)",
            "Keluar"
        ]

        for i, access_menu in enumerate(active_access_menu, start = 1):
            print(f"{i}.  {access_menu}")
        active = (prompt("\nPilih Menu") or "") .strip()
        match active:
            case "1":
                wallet = _handle_create_wallet()
                if wallet is not None:
                    _wallet_session(wallet, node)
            case "2":
                wallet = _handle_unlock_wallet()
                if wallet is not None:
                    _wallet_session(wallet, node)
            case "3":
                wallet = _handle_import_wallet()
                if wallet is not None:
                    _wallet_session(wallet, node)
            case "4" | "0":
                clear_screen()
                print("\nKeluar..")
                return
            case _:
                print("\nPilihan tidak valid!")
                pause()


if __name__ == "__main__":
    main()
