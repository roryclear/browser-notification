from __future__ import annotations
import struct
from typing import Callable, Literal, Optional, Union, overload

from Crypto.Hash import HMAC

Buffer = Union[bytes, bytearray, memoryview]
RNG = Callable[[int], bytes]
PRF = Callable[[bytes, bytes], bytes]

def _HKDF_extract(salt: Buffer, ikm: Buffer, hashmod) -> bytes:
    prk = HMAC.new(salt, ikm, digestmod=hashmod).digest()
    return prk


def _HKDF_expand(prk: Buffer, info: Buffer, L: int, hashmod) -> bytes:
    t = [b""]
    n = 1
    tlen = 0
    while tlen < L:
        hmac = HMAC.new(prk, t[-1] + info + struct.pack("B", n), digestmod=hashmod)
        t.append(hmac.digest())
        tlen += hashmod.digest_size
        n += 1
    okm = b"".join(t)
    return okm[:L]


@overload
def HKDF(
    master: Buffer,
    key_len: int,
    salt: Optional[Buffer],
    hashmod,
    num_keys: Literal[1] = 1,
    context: Optional[Buffer] = None,
) -> bytes: ...


@overload
def HKDF(
    master: Buffer,
    key_len: int,
    salt: Optional[Buffer],
    hashmod,
    num_keys: int,
    context: Optional[Buffer] = None,
) -> Union[bytes, list[bytes]]: ...


def HKDF(
    master: Buffer,
    key_len: int,
    salt: Optional[Buffer],
    hashmod,
    num_keys: int = 1,
    context: Optional[Buffer] = None,
) -> Union[bytes, list[bytes]]:
    output_len = key_len * num_keys
    if output_len > (255 * hashmod.digest_size):
        raise ValueError("Too much secret data to derive")
    if not salt:
        salt = b"\x00" * hashmod.digest_size
    if context is None:
        context = b""

    prk = _HKDF_extract(salt, master, hashmod)
    okm = _HKDF_expand(prk, context, output_len, hashmod)

    if num_keys == 1:
        return okm[:key_len]
    kol = [okm[idx : idx + key_len] for idx in range(0, output_len, key_len)]
    return list(kol[:num_keys])
