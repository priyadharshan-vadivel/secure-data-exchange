from cryptography.hazmat.primitives import serialization
from src.core.hybrid_crypto import HybridCrypto, SecurePayload


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


if __name__ == "__main__":
    sender_priv = load_private_key("private.pem")
    receiver_pub = load_public_key("public.pem")

    message = b"Confidential data exchange message."
    payload = HybridCrypto.encrypt(sender_priv, receiver_pub, message)

    with open("encrypted.bin", "wb") as f:
        f.write(payload.encrypted_key + payload.signature + payload.ciphertext)

    print("✅ Data encrypted successfully.")
