from __future__ import annotations
from typing import Callable, Optional, Protocol, Union, Any
from Crypto.Math.Numbers import Integer
from Crypto.Util.number import long_to_bytes


class Hash(Protocol):
    def digest(self) -> bytes: ...


class DssSigScheme:
    def __init__(self, key: Union[Any, Any], encoding: str, order: Integer) -> None:
        self._key = key
        self._order = order

        self._order_bits = self._order.size_in_bits()
        self._order_bytes = (self._order_bits - 1) // 8 + 1

    def sign(self, msg_hash: Hash) -> bytes:
        nonce = self._compute_nonce(msg_hash)
        z = Integer.from_bytes(msg_hash.digest()[: self._order_bytes])
        sig_pair = self._key._sign(z, nonce)
        output = b"".join([long_to_bytes(x, self._order_bytes) for x in sig_pair])
        return output

class FipsEcDsaSigScheme(DssSigScheme):
    def __init__(
        self, key: Any, encoding: str, order: Integer, randfunc: Optional[Callable[[int], bytes]]
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