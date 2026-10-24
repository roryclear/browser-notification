import json
import requests

from AES import aes_encrypt

if __name__ == "__main__":
    data = json.dumps({
        "title": "Notification",
        "body": "Hello from python!",
    }).encode("utf8")

    with open("notif_keys.json") as f: subscription_info = json.load(f)


    encoded_data, headers, endpoint = aes_encrypt(data)

    response = requests.post(
        endpoint,
        timeout=30,
        data=encoded_data,
        headers=headers,
    )

    print("HTTP status:", response.status_code)
    print("Response:", response.text)