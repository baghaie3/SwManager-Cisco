# crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def get_backup_key() -> bytes:
    key_hex = os.environ.get("STEGO_BACKUP_KEY_HEX")
    if not key_hex:
        raise RuntimeError("STEGO_BACKUP_KEY_HEX not set")
    key = bytes.fromhex(key_hex)
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key length")
    return key

def encrypt_backup(plaintext: bytes) -> bytes:
    key = get_backup_key()
    aesgcm = AESGCM(key)
    # 96-bit nonce (12 bytes) recommended for GCM
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # store nonce + ciphertext together
    return nonce + ciphertext

def decrypt_backup(data: bytes) -> bytes:
    key = get_backup_key()
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
