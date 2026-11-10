import base64
from cryptography.hazmat.bindings._rust import PrivateFormat
from cryptography.hazmat.bindings._rust import Encoding
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
import abc

class NoEncryption(metaclass=abc.ABCMeta): pass
class EllipticCurve(metaclass=abc.ABCMeta): pass
class SECP256R1(EllipticCurve):
    name = "secp256r1"
    key_size = 256
    group_order = (
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    )

private_key = rust_openssl.ec.generate_private_key(SECP256R1())
with open("vapid_private.pem", "wb") as file:
    key = private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption(),)
    file.write(key)
    file.close()

public_bytes = private_key.public_key().public_bytes()
public_key = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()

print("Private key saved to vapid_private.pem")
print("Public key:", public_key)