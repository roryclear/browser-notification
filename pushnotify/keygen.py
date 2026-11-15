import base64, subprocess, os

def keygen():
  private_key = subprocess.check_output([
    "openssl", "genpkey",
    "-algorithm", "EC",
    "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-outform", "PEM",
  ])
  os.makedirs("notify_keys", exist_ok=True)
  with open("notify_keys/vapid_private.pem", "wb") as file: file.write(private_key)
  public_bytes = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private_key,)[-65:]
  return (base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode())