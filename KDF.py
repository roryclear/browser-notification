from __future__ import annotations
import struct

def strxor(term1, term2, length=None): return bytes(a ^ b for a, b in zip(term1[:length], term2[:length]))

class HMAC:
    def __init__(self, key, msg = b"", digestmod =None) -> None:
        self.digest_size = digestmod.digest_size
        self._digestmod = digestmod
    
        if len(key) <= digestmod.block_size:
            key_0 = key + b"\x00" * (digestmod.block_size - len(key))
        else:
            hash_k = digestmod.new(key).digest()
            key_0 = hash_k + b"\x00" * (digestmod.block_size - len(hash_k))

        key_0_ipad = strxor(key_0, b"\x36" * len(key_0))
        self._inner = digestmod.new(key_0_ipad)
        self._inner.update(msg)
        key_0_opad = strxor(key_0, b"\x5c" * len(key_0))
        self._outer = digestmod.new(key_0_opad)

    def digest(self) -> bytes:
        frozen_outer_hash = self._outer.copy()
        frozen_outer_hash.update(self._inner.digest())
        return frozen_outer_hash.digest()

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
