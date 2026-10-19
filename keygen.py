
import base64
from py_vapid import Vapid
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

vapid = Vapid()
vapid.generate_keys()
vapid.save_key("vapid_private.pem")

public_bytes = vapid.public_key.public_bytes(
    Encoding.X962,
    PublicFormat.UncompressedPoint
)

public_key = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()

print("Private key saved to vapid_private.pem")
print("Public key:", public_key)