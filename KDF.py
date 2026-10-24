from __future__ import annotations
import struct
from HMAC import HMAC

def _HKDF_expand(prk, info, L: int, hashmod) -> bytes:
    t = [b""]
    n = 1
    tlen = 0
    while tlen < L:
        hmac = HMAC(prk, t[-1] + info + struct.pack("B", n), digestmod=hashmod)
        t.append(hmac.digest())
        tlen += hashmod.digest_size
        n += 1
    okm = b"".join(t)
    return okm[:L]

def HKDF(master, key_len, salt, hashmod, context):
    prk = HMAC(salt, master, digestmod=hashmod).digest()
    okm = _HKDF_expand(prk, context, key_len, hashmod)
    return okm[:key_len]
