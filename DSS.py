from __future__ import annotations
from typing import Callable, Optional, Protocol, Union, Any
from Crypto.Math._IntegerNat import IntegerNat as Integer
import operator

def ceil_div(n: int, d: int) -> int:
    """Return ceil(n/d), that is, the smallest integer r such that r*d >= n"""

    if d == 0:
        raise ZeroDivisionError()
    if (n < 0) or (d < 0):
        raise ValueError("Non positive values")
    r, q = divmod(n, d)
    if (n != 0) and (q != 0):
        r += 1
    return r

def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    n = operator.index(n)
    if n < 0 or blocksize < 0:
        raise ValueError("Values must be non-negative")

    length = max((n.bit_length() + 7) // 8, 1)
    if blocksize > 0:
        length = ceil_div(length, blocksize) * blocksize
    return n.to_bytes(length, "big")

class Hash(Protocol):
    def digest(self) -> bytes: ...

class DssSigScheme:
    def __init__(self, key: Union[Any, Any], encoding: str, order: Any) -> None:
        self._key = key
        self._order = order

        self._order_bits = self._order.size_in_bits()
        self._order_bytes = (self._order_bits - 1) // 8 + 1

    def sign(self, msg_hash: Hash) -> bytes:
        nonce = self._compute_nonce(msg_hash)
        z = int.from_bytes(msg_hash.digest()[:self._order_bytes], byteorder="big")
        sig_pair = self._key._sign(z, nonce)
        output = b"".join([long_to_bytes(x, self._order_bytes) for x in sig_pair])
        return output

class FipsEcDsaSigScheme(DssSigScheme):
    def __init__(
        self, key: Any, encoding: str, order: Any, randfunc: Optional[Callable[[int], bytes]]
    ) -> None:
        super().__init__(key, encoding, order)
        self._randfunc = randfunc

    def _compute_nonce(self, msg_hash):
        return Integer.random_range(
            min_inclusive=1, max_exclusive=self._key._curve.order, randfunc=self._randfunc
        )



def new(
    key: Union[Any, Any],
    mode: str,
    encoding: str = "binary",
    randfunc: Optional[Callable[[int], bytes]] = None):
    order = key._curve.order
    return FipsEcDsaSigScheme(key, encoding, order, randfunc)