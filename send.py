
import json
import base64
from typing import cast
from urllib.parse import urlparse
import requests
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os, struct
import time
import copy

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def num_to_bytes(n, pad_to):
    h = "%x" % n
    r = binascii.unhexlify("0" * (len(h) % 2) + h)
    return b"\x00" * (pad_to - len(r)) + r

def sign(claims, key):
    header = b64urlencode(b"""{"typ":"JWT","alg":"ES256"}""")
    # Unfortunately, chrome seems to require the claims to be sorted.
    claims = b64urlencode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf8")
    )
    token = "{}.{}".format(header, claims)
    rsig = key.sign(token.encode("utf8"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(rsig)
    sig = b64urlencode(num_to_bytes(r, 32) + num_to_bytes(s, 32))
    return "{}.{}".format(token, sig)

def b64urldecode(data):
    padded = data.replace(b"+", b"-").replace(b"/", b"_") + b"===="[len(data) % 4 :]
    return base64.urlsafe_b64decode(padded)

def b64urlencode(data): return base64.urlsafe_b64encode(data).replace(b"=", b"").decode("utf8")

class Vapid:
    def __init__(self, private_key=None):
        self._schema = "vapid"
        self.conf = {}
        self._private_key = private_key
        self._public_key = self._private_key.public_key()

    @classmethod
    def from_pem(cls, private_key): return cls.from_der(b"".join(private_key.splitlines()[1:-1]))

    @classmethod
    def from_der(cls, private_key):
        key = serialization.load_der_private_key(b64urldecode(private_key), password=None, backend=default_backend())
        return cls(key)

    @classmethod
    def from_file(cls, private_key_file=None):
        with open(private_key_file, "r") as file:
            private_key = file.read()
        vapid = cls.from_pem(private_key.encode("utf8"))
        return vapid      

    def _base_sign(self, claims):
        cclaims = copy.deepcopy(claims)
        cclaims["exp"] = int(time.time()) + 86400
        return cclaims

    def sign(self, claims):
        sig = sign(self._base_sign(claims), self._private_key)
        pkey = self._public_key.public_bytes(
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
        parts = {}
        for tok in pref_tok[1].split(","):
            kv = tok.split("=", 1)
            parts[kv[0]] = kv[1]
        kp = cls().from_raw_public(parts["k"].encode())
        tokens = parts["t"].rsplit(".", 1)
        return kp.verify_token(
            validation_token=tokens[0].encode(), verification_token=tokens[1]
        )

MAX_RECORD_SIZE = pow(2, 31) - 1
MIN_RECORD_SIZE = 3
KEY_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16

versions = {
    "aes128gcm": {"pad": 1},
    "aesgcm": {"pad": 2},
    "aesgcm128": {"pad": 1},
}

def iv(base, counter):
    (mask,) = struct.unpack("!Q", base[4:])
    return base[:4] + struct.pack("!Q", counter ^ mask)

def derive_key(salt, private_key, dh, auth_secret):
    context = b""
    keyinfo = ""
    nonceinfo = ""

    pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dh)
    encoded = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    sender_pub_key = encoded
    receiver_pub_key = dh
    context = b"WebPush: info\x00" + receiver_pub_key + sender_pub_key
    secret = private_key.exchange(ec.ECDH(), pubkey)
    keyinfo = b"Content-Encoding: aes128gcm\x00"
    nonceinfo = b"Content-Encoding: nonce\x00"

    info = context
    hkdf_auth = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=auth_secret,
        info=info,
        backend=default_backend(),
    )
    secret = hkdf_auth.derive(secret)

    hkdf_key = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=keyinfo,
        backend=default_backend(),
    )
    hkdf_nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=NONCE_LENGTH,
        salt=salt,
        info=nonceinfo,
        backend=default_backend(),
    )
    return hkdf_key.derive(secret), hkdf_nonce.derive(secret)

def encrypt(
    content,
    private_key=None,
    dh=None,
    auth_secret=None,
):
    rs=4096
    def encrypt_record(key, nonce, counter, buf):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv(nonce, counter)),
            backend=default_backend(),
        ).encryptor()
        data = encryptor.update(buf + (b"\x02"))
        data += encryptor.finalize()
        data += encryptor.tag
        return data

    def compose_aes128gcm(salt, content, rs, keyid):
        header = salt
        header += struct.pack("!L", rs)
        header += struct.pack("!B", len(keyid))
        header += keyid
        return header + content

    salt = os.urandom(16)
    key_, nonce_ = derive_key(salt=salt, private_key=private_key, dh=dh, auth_secret=auth_secret,)

    overhead = versions["aes128gcm"]["pad"]
    overhead += 16
    end = len(content)
    chunk_size = rs - overhead
    result = b""
    counter = 0

    for i in list(range(0, end, chunk_size)):
        result += encrypt_record(key_, nonce_, counter, content[i : i + chunk_size])
        counter += 1
    kid = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return compose_aes128gcm(salt, result, rs, keyid=kid)


def _repad(data: bytes) -> bytes: return data + b"===="[: len(data) % 4]

with open("notif_keys.json") as f: subscription_info = json.load(f)

data = json.dumps({"title": "Notification", "body": "Hello from python!"})

vapid_private_key = "vapid_private.pem"
vapid_claims = {"sub": "mailto:fake@fake.invalid"}

url = urlparse(cast(str, subscription_info.get("endpoint")))
aud = f"{url.scheme}://{url.netloc}"
vapid_claims["aud"] = aud
vv = Vapid.from_file(private_key_file=vapid_private_key)
headers = vv.sign(vapid_claims)

endpoint = subscription_info["endpoint"]
p256dh = bytes(cast(str, subscription_info["keys"]["p256dh"]).encode("utf8"))
auth = bytes(cast(str, subscription_info["keys"]["auth"]).encode("utf8"))
receiver_key = base64.urlsafe_b64decode(_repad(cast(bytes, p256dh)))
auth_key = base64.urlsafe_b64decode(_repad(cast(bytes, auth)))

data = data.encode()

server_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
encoded_data = encrypt(data, private_key=server_key, dh=receiver_key, auth_secret=auth_key)

headers.update({"content-encoding": "aes128gcm",})
headers["ttl"] = "0"
response = requests.post(endpoint,timeout=10000, data=encoded_data, headers=headers)

print("HTTP status:", response.status_code)
print("Response:", response.text)