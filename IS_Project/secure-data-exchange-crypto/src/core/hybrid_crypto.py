"""
Hybrid Cryptographic System (RSA + AES + Signature)
"""

import os
from dataclasses import dataclass
from .aes import AES
from .rsa import RSAKey
from .signature import Signature
from .hkdf import derive_key


@dataclass
class SecurePayload:
    encrypted_key: bytes
    ciphertext: bytes
    signature: bytes


class HybridCrypto:
    @staticmethod
    def encrypt(sender_private, receiver_public, data: bytes) -> SecurePayload:
        master_secret = os.urandom(32)
        aes_key = derive_key(master_secret)

        ciphertext = AES.encrypt(aes_key, data)
        encrypted_key = RSAKey.encrypt(receiver_public, master_secret)
        signature = Signature.sign(sender_private, ciphertext)

        return SecurePayload(encrypted_key, ciphertext, signature)

    @staticmethod
    def decrypt(receiver_private, sender_public, payload: SecurePayload) -> bytes:
        master_secret = RSAKey.decrypt(receiver_private, payload.encrypted_key)
        aes_key = derive_key(master_secret)

        if not Signature.verify(sender_public, payload.signature, payload.ciphertext):
            raise ValueError("❌ Signature verification failed.")

        return AES.decrypt(aes_key, payload.ciphertext)
