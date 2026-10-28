
import base64
from py_vapid import Vapid
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec


def generate_keys():
    return ec.generate_private_key(ec.SECP256R1(), None)

vapid = Vapid()
vapid.private_key = generate_keys()
vapid.save_key("vapid_private.pem")

public_bytes = vapid.public_key.public_bytes(
    Encoding.X962,
    PublicFormat.UncompressedPoint
)

public_key = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()

print("Private key saved to vapid_private.pem")
print("Public key:", public_key)