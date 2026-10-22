import json
import base64
import binascii
import os
import struct
import time
import copy
import requests

from typing import cast
from urllib.parse import urlparse

import SHA256
import DSS
import AES
import ECC

from KDF import HKDF

def num_to_bytes(n, pad_to):
    h = "%x" % n
    r = binascii.unhexlify("0" * (len(h) % 2) + h)
    return b"\x00" * (pad_to - len(r)) + r

def sign(claims, key):
    header = b64urlencode(b'{"typ":"JWT","alg":"ES256"}')
    claims = b64urlencode(
        json.dumps(
            claims, separators=(",", ":"), sort_keys=True
        ).encode("utf8")
    )

    token = "{}.{}".format(header, claims)

    signer = DSS.new(key, "fips-186-3", encoding="binary")

    # todo patch throw in lib
    import hashlib
    signature = signer.sign(hashlib.sha256(token.encode("utf8")))

    return "{}.{}".format(token, b64urlencode(signature))

def b64urldecode(data):
    padded = data.replace(b"+", b"-").replace(b"/", b"_") + b"===="[len(data) % 4 :]
    return base64.urlsafe_b64decode(padded)

def b64urlencode(data): return base64.urlsafe_b64encode(data).replace(b"=", b"").decode("utf8")

class Vapid:
    def __init__(self, private_key):
        self._schema = "vapid"
        self.conf = {}
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def from_pem(cls, private_key):
        return cls(ECC.import_key(private_key))

    @classmethod
    def from_der(cls, private_key):
        der = b64urldecode(private_key)
        return cls(ECC.import_key(der))

    @classmethod
    def from_file(cls, private_key_file=None):
        with open(private_key_file, "rb") as f:
            return cls.from_pem(f.read())

    def _base_sign(self, claims):
        cclaims = copy.deepcopy(claims)
        cclaims["exp"] = int(time.time()) + 86400
        return cclaims

    def sign(self, claims):
        token = sign(self._base_sign(claims), self._private_key)

        public_key = self._public_key.export_key(format="SEC1")

        return {
            "Authorization": "{} t={},k={}".format(
                self._schema, token, b64urlencode(public_key)
            )
        }

MAX_RECORD_SIZE = pow(2, 31) - 1
MIN_RECORD_SIZE = 3
KEY_LENGTH = 16
NONCE_LENGTH = 12


def iv(base, counter):
    (mask,) = struct.unpack("!Q", base[4:])
    return base[:4] + struct.pack("!Q", counter ^ mask)


def derive_key(salt, private_key, dh, auth_secret):
    receiver_pub = ECC.import_key(dh, curve_name="P-256")

    # ECDH: X coordinate of the shared point, encoded to 32 bytes.
    shared_point = receiver_pub.pointQ * private_key._d
    secret = int(shared_point.x).to_bytes(32, "big")

    sender_pub = private_key.public_key().export_key(format="SEC1")

    context = b"WebPush: info\x00" + dh + sender_pub

    secret = HKDF(
        secret,
        32,
        auth_secret,
        SHA256,
        context=context,
    )

    key = HKDF(
        secret,
        KEY_LENGTH,
        salt,
        SHA256,
        context=b"Content-Encoding: aes128gcm\x00",
    )

    nonce = HKDF(
        secret,
        NONCE_LENGTH,
        salt,
        SHA256,
        context=b"Content-Encoding: nonce\x00",
    )

    return key, nonce


def encrypt(content, private_key=None, dh=None, auth_secret=None):
    rs = 4096
    def encrypt_record(key, nonce, counter, buf):
        cipher = AES.new(
            key,
            AES.MODE_GCM,
            nonce=iv(nonce, counter),
            mac_len=16,
        )

        ciphertext, tag = cipher.encrypt_and_digest(buf + b"\x02")
        return ciphertext + tag

    def compose_aes128gcm(salt, content, rs, keyid):
        header = salt
        header += struct.pack("!L", rs)
        header += struct.pack("!B", len(keyid))
        header += keyid
        return header + content

    salt = os.urandom(16)

    key, nonce = derive_key(
        salt=salt,
        private_key=private_key,
        dh=dh,
        auth_secret=auth_secret,
    )

    overhead = 1 + 16
    chunk_size = rs - overhead

    result = b""
    counter = 0

    for i in range(0, len(content), chunk_size):
        result += encrypt_record(
            key, nonce, counter, content[i:i + chunk_size]
        )
        counter += 1

    public_key = private_key.public_key().export_key(format="SEC1")

    return compose_aes128gcm(
        salt, result, rs, keyid=public_key
    )


def _repad(data: bytes) -> bytes: return data + b"===="[: len(data) % 4]

with open("notif_keys.json") as f:
    subscription_info = json.load(f)

data = json.dumps({
    "title": "Notification",
    "body": "Hello from python!",
}).encode("utf8")

endpoint = subscription_info["endpoint"]
url = urlparse(endpoint)

vapid_claims = {
    "sub": "mailto:fake@fake.invalid",
    "aud": f"{url.scheme}://{url.netloc}",
}

vv = Vapid.from_file("vapid_private.pem")
headers = vv.sign(vapid_claims)

receiver_key = b64urldecode(
    subscription_info["keys"]["p256dh"].encode("ascii")
)
auth_key = b64urldecode(
    subscription_info["keys"]["auth"].encode("ascii")
)

server_key = ECC.generate(curve="P-256")

encoded_data = encrypt(
    data,
    private_key=server_key,
    dh=receiver_key,
    auth_secret=auth_key,
)

headers.update({
    "Content-Encoding": "aes128gcm",
    "TTL": "60",
})

response = requests.post(
    endpoint,
    timeout=30,
    data=encoded_data,
    headers=headers,
)

print("HTTP status:", response.status_code)
print("Response:", response.text)