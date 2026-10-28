
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec

class Vapid01(object):
    """Minimal VAPID Draft 01 signature generation library.

    https://tools.ietf.org/html/draft-ietf-webpush-vapid-01

    """

    _private_key = None
    _public_key = None
    _schema = "WebPush"

    def __init__(self, private_key=None, conf=None):
        """Initialize VAPID with an optional private key.

        :param private_key: A private key object
        :type private_key: ec.EllipticCurvePrivateKey

        """
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
    def from_file(cls, private_key_file=None):
        """Initialize VAPID using a file containing a private key in PEM or
        DER format.

        :param private_key_file: Name of the file containing the private key
        :type private_key_file: str

        """
        if not os.path.isfile(private_key_file):
            logging.info("Private key not found, generating key...")
            vapid = cls()
            vapid.generate_keys()
            vapid.save_key(private_key_file)
            return vapid
        with open(private_key_file, "r") as file:
            private_key = file.read()
        try:
            if "-----BEGIN" in private_key:
                vapid = cls.from_pem(private_key.encode("utf8"))
            else:
                vapid = cls.from_der(private_key.encode("utf8"))
            return vapid
        except Exception as exc:
            logging.error("Could not open private key file: %s", repr(exc))
            raise VapidException(exc)

    @classmethod
    def from_string(cls, private_key):
        """Initialize VAPID using a string containing the private key. This
        will try to determine if the key is in RAW or DER format.

        :param private_key: String containing the key info
        :type private_key: str

        """

        pkey = private_key.encode().replace(b"\n", b"")
        key = b64urldecode(pkey)
        if len(key) == 32:
            return cls.from_raw(pkey)
        return cls.from_der(pkey)

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
    def private_key(self):
        """The VAPID private ECDSA key"""
        if not self._private_key:
            raise VapidException("No private key. Call generate_keys()")
        return self._private_key

    @private_key.setter
    def private_key(self, value):
        """Set the VAPID private ECDSA key

        :param value: the byte array containing the private ECDSA key data
        :type value: ec.EllipticCurvePrivateKey

        """
        self._private_key = value
        if value:
            self._public_key = self.private_key.public_key()

    @property
    def public_key(self):
        """The VAPID public ECDSA key

        The public key is currently read only. Set it via the `.private_key`
        method. This will autogenerate a public and private key if no value
        has been set.

        :returns ec.EllipticCurvePublicKey

        """
        return self._public_key

    def generate_keys(self):
        """Generate a valid ECDSA Key Pair."""
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def private_pem(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def save_key(self, key_file):
        """Save the private key to a PEM file.

        :param key_file: The file path to save the private key data
        :type key_file: str

        """
        with open(key_file, "wb") as file:
            file.write(self.private_pem())
            file.close()

    def save_public_key(self, key_file):
        """Save the public key to a PEM file.
        :param key_file: The name of the file to save the public key
        :type key_file: str

        """
        with open(key_file, "wb") as file:
            file.write(self.public_pem())
            file.close()

    def verify_token(self, validation_token, verification_token):
        """Internally used to verify the verification token is correct.

        :param validation_token: Provided validation token string
        :type validation_token: str
        :param verification_token: Generated verification token
        :type verification_token: str
        :returns: Boolean indicating if verifictation token is valid.
        :rtype: boolean

        """
        hsig = b64urldecode(verification_token.encode("utf8"))
        r = int(binascii.hexlify(hsig[:32]), 16)
        s = int(binascii.hexlify(hsig[32:]), 16)
        try:
            self.public_key.verify(
                ecutils.encode_dss_signature(r, s),
                validation_token,
                signature_algorithm=ec.ECDSA(hashes.SHA256()),
            )
            return True
        except InvalidSignature:
            return False

    def _base_sign(self, claims):
        cclaims = copy.deepcopy(claims)
        if not cclaims.get("exp"):
            cclaims["exp"] = int(time.time()) + 86400
        if not self.conf.get("no-strict", False):
            valid = _check_sub(cclaims.get("sub", ""))
        else:
            valid = cclaims.get("sub") is not None
        if not valid:
            raise VapidException(
                "Missing 'sub' from claims. "
                "'sub' is your admin email as a mailto: link."
            )
        if not re.match(
            r"^https?://[^/:]+(:\d+)?$", cclaims.get("aud", ""), re.IGNORECASE
        ):
            raise VapidException(
                "Missing 'aud' from claims. "
                "'aud' is the scheme, host and optional port for this "
                "transaction e.g. https://example.com:8080"
            )
        return cclaims

    def sign(self, claims, crypto_key=None):
        """Sign a set of claims.
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
        pkey = "p256ecdsa="
        pkey += b64urlencode(
            self.public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        )
        if crypto_key:
            crypto_key = crypto_key + ";" + pkey
        else:
            crypto_key = pkey

        return {
            "Authorization": "{} {}".format(self._schema, sig.strip("=")),
            "Crypto-Key": crypto_key,
        }

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