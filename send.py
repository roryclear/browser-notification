
import json

import base64
from typing import cast
from urllib.parse import urlparse
import http_ece
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from py_vapid import Vapid

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
encoded_data = http_ece.encrypt(data,
    private_key=server_key,
    dh=receiver_key,
    auth_secret=auth_key,
    version="aes128gcm",
)

headers.update({"content-encoding": "aes128gcm",})
headers["ttl"] = "0"
response = requests.post(endpoint,timeout=10000, data=encoded_data, headers=headers)

print("HTTP status:", response.status_code)
print("Response:", response.text)
