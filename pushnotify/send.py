import json
import urllib.request

from .AES import aes_encrypt

def send(title="Notif", body="Hello there"):
  data = json.dumps({"title": title, "body": body,}).encode("utf8")
  encoded_data, headers, endpoint = aes_encrypt(data)
  req = urllib.request.Request(url=endpoint, data=encoded_data, headers=headers, method="POST",)
  with urllib.request.urlopen(req, timeout=30) as response:
    print("HTTP status:", response.status)
    print("Response:", response.read().decode("utf8"))