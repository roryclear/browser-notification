
import base64
from py_vapid import Vapid01
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec

class Vapid02(Vapid01):
    _schema = "vapid"

    def sign(self, claims, crypto_key=None):
        """Generate an authorization token

        :param claims: JSON object containing the JWT claims to use.
        :type claims: dict
        :param crypto_key: Optional existing crypto_key header content. The
            vapid public key will be appended to this data.
        :type crypto_key: str
        :returns: a hash containing the header fields to use in
            the subscription update.
        :rtype: dict
        """
        sig = sign(self._base_sign(claims), self.private_key)
        pkey = self.public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return {
            "Authorization": "{schema} t={t},k={k}".format(
                schema=self._schema, t=sig, k=b64urlencode(pkey)
            )
        }

    @classmethod
    def verify(cls, auth):
        pref_tok = auth.rsplit(" ", 1)
        assert pref_tok[0].lower() == cls._schema, "Incorrect schema specified"
        parts = {}
        for tok in pref_tok[1].split(","):
            kv = tok.split("=", 1)
            parts[kv[0]] = kv[1]
        assert "k" in parts.keys(), "Auth missing public key 'k' value"
        assert "t" in parts.keys(), "Auth missing token set 't' value"
        kp = cls().from_raw_public(parts["k"].encode())
        tokens = parts["t"].rsplit(".", 1)
        return kp.verify_token(
            validation_token=tokens[0].encode(), verification_token=tokens[1]
        )

Vapid = Vapid02

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