from cryptography.hazmat.primitives import serialization
from src.core.hybrid_crypto import HybridCrypto, SecurePayload


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


if __name__ == "__main__":
    receiver_priv = load_private_key("private.pem")
    sender_pub = load_public_key("public.pem")

    with open("encrypted.bin", "rb") as f:
        data = f.read()

    encrypted_key = data[:256]
    signature = data[256:512]
    ciphertext = data[512:]

    payload = SecurePayload(encrypted_key, ciphertext, signature)
    plaintext = HybridCrypto.decrypt(receiver_priv, sender_pub, payload)

    print("✅ Decrypted message:", plaintext.decode())
