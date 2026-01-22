"""
AES-GCM Symmetric Encryption Module
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AES:
    KEY_SIZE = 32  # AES-256
    NONCE_SIZE = 12  # Recommended size for GCM

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(AES.KEY_SIZE)

    @staticmethod
    def encrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(AES.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)
        return nonce + ciphertext

    @staticmethod
    def decrypt(key: bytes, encrypted_data: bytes, aad: bytes = b"") -> bytes:
        nonce = encrypted_data[:AES.NONCE_SIZE]
        ciphertext = encrypted_data[AES.NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
