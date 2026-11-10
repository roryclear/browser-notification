
import base64
import subprocess

private_key = subprocess.check_output([
    "openssl", "genpkey",
    "-algorithm", "EC",
    "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-outform", "PEM",
])

with open("vapid_private.pem", "wb") as file: file.write(private_key)
public_bytes = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private_key,)

public_bytes = public_bytes[-65:]

public_key = (
    base64.urlsafe_b64encode(public_bytes)
    .rstrip(b"=")
    .decode()
)

print("Private key saved to vapid_private.pem")
print("Public key:", public_key)
