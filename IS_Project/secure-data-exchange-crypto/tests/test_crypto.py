from src.core.rsa import RSAKey
from src.core.hybrid_crypto import HybridCrypto

sender_priv, sender_pub = RSAKey.generate()
recv_priv, recv_pub = RSAKey.generate()

msg = b"Secure test message."

payload = HybridCrypto.encrypt(sender_priv, recv_pub, msg)
result = HybridCrypto.decrypt(recv_priv, sender_pub, payload)

assert msg == result
print("✅ All tests passed successfully.")
