from src.core.rsa import RSAKey
from src.pki.utils import save_private_key, save_public_key


if __name__ == "__main__":
    priv, pub = RSAKey.generate()
    save_private_key(priv, "private.pem")
    save_public_key(pub, "public.pem")
    print("✅ RSA keys generated.")
