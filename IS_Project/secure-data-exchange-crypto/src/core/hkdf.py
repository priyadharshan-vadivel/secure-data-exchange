"""
HKDF Key Derivation Module
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_key(secret: bytes, context: bytes = b"secure-data-exchange") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(secret)
