import json
import urllib.request

from AES import aes_encrypt

if __name__ == "__main__":
    data = json.dumps({
        "title": "Notification",
        "body": "Hello from python!",
    }).encode("utf8")

    with open("notif_keys.json") as f:
        subscription_info = json.load(f)

    encoded_data, headers, endpoint = aes_encrypt(data)

    req = urllib.request.Request(
        url=endpoint,
        data=encoded_data,
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        print("HTTP status:", response.status)
        print("Response:", response.read().decode("utf8"))