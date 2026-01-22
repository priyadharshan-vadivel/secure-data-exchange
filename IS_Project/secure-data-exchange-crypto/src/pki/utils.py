from cryptography.hazmat.primitives import serialization


def save_private_key(key, filename: str):
    with open(filename, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def save_public_key(key, filename: str):
    with open(filename, "wb") as f:
        f.write(
            key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
