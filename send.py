
import json
from pywebpush import webpush

with open("subscription.json") as f:
    subscription = json.load(f)

response = webpush(
    subscription_info=subscription,
    data=json.dumps({
        "title": "Notification",
        "body": "Hello from python!"
    }),
    vapid_private_key="vapid_private.pem",
    vapid_claims={"sub": "mailto:fake@fake.invalid"}
)

print("HTTP status:", response.status_code)
print("Response:", response.text)
