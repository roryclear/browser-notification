import json
import binascii
import requests
from urllib.parse import urlparse

from AES import aes_encrypt
from AES import Vapid

def num_to_bytes(n, pad_to):
    h = "%x" % n
    r = binascii.unhexlify("0" * (len(h) % 2) + h)
    return b"\x00" * (pad_to - len(r)) + r

if __name__ == "__main__":
    data = json.dumps({
        "title": "Notification",
        "body": "Hello from python!",
    }).encode("utf8")

    with open("notif_keys.json") as f: subscription_info = json.load(f)

    endpoint = subscription_info["endpoint"]
    url = urlparse(endpoint)

    vapid_claims = {
        "sub": "mailto:fake@fake.invalid",
        "aud": f"{url.scheme}://{url.netloc}",
    }

    vv = Vapid.from_file("vapid_private.pem")
    headers = vv.sign(vapid_claims)

    encoded_data, headers = aes_encrypt(
        data,
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