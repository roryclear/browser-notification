import json
import base64
import binascii
import time
import copy
import requests
from urllib.parse import urlparse

import DSS
from AES import aes_encrypt
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


if __name__ == "__main__":
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

    encoded_data, headers = aes_encrypt(
        data,
        dh=receiver_key,
        auth_secret=auth_key,
        headers=headers
    )

    response = requests.post(
        endpoint,
        timeout=30,
        data=encoded_data,
        headers=headers,
    )

    print("HTTP status:", response.status_code)
    print("Response:", response.text)