from __future__ import annotations

from typing import Optional

__all__ = ["encode", "decode"]

import re
from binascii import a2b_base64

def decode(pem_data: str, passphrase: Optional[bytes] = None) -> tuple[bytes, str, bool]:
    r = re.compile(r"\s*-----BEGIN (.*)-----\s+")
    m = r.match(pem_data)
    marker = m.group(1)
    lines = pem_data.replace(" ", "").split()
    data = a2b_base64("".join(lines[1:-1]))
    enc_flag = False

    return (data, marker, enc_flag)