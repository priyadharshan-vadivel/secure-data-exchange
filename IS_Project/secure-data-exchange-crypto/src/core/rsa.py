"""
RSA Asymmetric Cryptography Module (OAEP)
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class RSAKey:
    @staticmethod
    def generate(bits: int = 2048):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return private_key, private_key.public_key()

    @staticmethod
    def encrypt(public_key, data: bytes) -> bytes:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def decrypt(private_key, encrypted_data: bytes) -> bytes:
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
