# Python-Text-Encryption with Argon2id + XChaCha20-Poly1305

# Required packages

# pip install pynacl argon2-cffi
# Encryption:
# python nfc_id_dencrypt.py encrypt
#
# Decryption:
# python nfc_id_dencrypt.py decrypt
#
#---

# -*- coding: utf-8 -*-

import os
import base64
from pathlib import Path

from nacl.secret import SecretBox
from argon2.low_level import hash_secret_raw, Type


# =========================
# Parameter
# =========================

SALT_SIZE = 32
KEY_SIZE = 32
ARGON_TIME_COST = 6
ARGON_MEMORY_COST = 65536*2   # 128 MB
ARGON_PARALLELISM = 4


# =========================
# Key derivation
# =========================


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


# =========================
# File encryption
# =========================


def encrypt_file():
    filename = input("Provide text file: ").strip()

    path = Path(filename)

    if not path.exists():
        print("File not found!")
        return

    password = input("Enter encryption code: ")

    with open(path, "r", encoding="utf-8") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)

    key = derive_key(password, salt)

    box = SecretBox(key)

    encrypted = box.encrypt(plaintext.encode("utf-8"))

    final_data = salt + encrypted

    encoded = base64.b64encode(final_data)

    output_file = path.stem + "_encrypted.txt"

    with open(output_file, "wb") as f:
        f.write(encoded)

    print(f"\nEncrypted file saved as: {output_file}")


# =========================
# File decryption
# =========================


def decrypt_file():
    filename = input("File to decrypt: ").strip()

    path = Path(filename)

    if not path.exists():
        print("File not found!")
        return

    password = input("Enter decryption code: ")

    try:
        with open(path, "rb") as f:
            encoded = f.read()

        data = base64.b64decode(encoded)

        salt = data[:SALT_SIZE]
        encrypted = data[SALT_SIZE:]

        key = derive_key(password, salt)

        box = SecretBox(key)

        decrypted = box.decrypt(encrypted)

        output_file = path.stem + "_decrypted.txt"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(decrypted.decode("utf-8"))

        print(f"\nDecrypted file saved as: {output_file}")

    except Exception as e:
        print("\nError during decryption!")
        print("Wrong code or damaged file.")
        print(str(e))


# =========================
# Main
# =========================


if __name__ == "__main__":

    mode = input("encrypt/decrypt: ").strip().lower()

    if mode == "encrypt":
        encrypt_file()

    elif mode == "decrypt":
        decrypt_file()

    else:
        print("Unknown mode.")
