
import os
import sys
from getpass import getpass


def clear_screen() -> None:
    if sys.platform == 'win32':
        os.system("cls")
    else:
        os.system("clear")

def pause(message: str = "\nTekan Enter untuk melanjutkan...\n") -> None:
    try:
        input(message)
    except(EOFError, KeyboardInterrupt):
        return

def prompt(label: str) -> str | int | None:
    try:
        value: str | int | None = input(f"{label}\n>> ")
        return value
    except(EOFError, KeyboardInterrupt):
        return

def prompt_password(label: str = "Password") -> str | None: 
    try:
        value = getpass(f"{label}: ")
        return value
    except(EOFError, KeyboardInterrupt):
        return

def print_header(title: str) -> None:
    print(f"\n========== {title} ==========\n")
