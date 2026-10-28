
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec

class Vapid01(object):
    _private_key = None
    _public_key = None
    _schema = "WebPush"

    def __init__(self, private_key=None, conf=None):
        if conf is None:
            conf = {}
        self.conf = conf
        self.private_key = private_key
        if private_key:
            self._public_key = self.private_key.public_key()

    @classmethod
    def from_pem(cls, private_key):
        return cls.from_der(b"".join(private_key.splitlines()[1:-1]))
    

    @classmethod
    def verify(cls, key, auth):
        """Verify a VAPID authorization token.

        :param key: base64 serialized public key
        :type key: str
        :param auth: authorization token
        type key: str

        """
        tokens = auth.rsplit(" ", 1)[1].rsplit(".", 1)
        kp = cls().from_raw_public(key.encode())
        return kp.verify_token(
            validation_token=tokens[0].encode(), verification_token=tokens[1]
        )

    @property
    def private_key(self): return self._private_key

    @private_key.setter
    def private_key(self, value):
        self._private_key = value
        if value:
            self._public_key = self._private_key.public_key()


    def save_key(self, key_file):
        with open(key_file, "wb") as file:
            key = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
            )
            file.write(key)
            file.close()

    def save_public_key(self, key_file):
        with open(key_file, "wb") as file:
            file.write(self.public_pem())
            file.close()

Vapid = Vapid01

def generate_keys():
    return ec.generate_private_key(ec.SECP256R1(), None)

vapid = Vapid()
vapid.private_key = generate_keys()
vapid.save_key("vapid_private.pem")

public_bytes = vapid._public_key.public_bytes(
    Encoding.X962,
    PublicFormat.UncompressedPoint
)

public_key = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()

print("Private key saved to vapid_private.pem")
print("Public key:", public_key)