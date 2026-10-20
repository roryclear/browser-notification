
import json
import base64
from typing import cast
from urllib.parse import urlparse
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from py_vapid import Vapid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os, struct

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