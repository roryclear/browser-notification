from typing import Union, Any
import secrets
import operator


def ceil_div(n: int, d: int) -> int:
    r, q = divmod(n, d)
    if (n != 0) and (q != 0): r += 1
    return r

def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    n = operator.index(n)
    length = max((n.bit_length() + 7) // 8, 1)
    if blocksize > 0:
        length = ceil_div(length, blocksize) * blocksize
    return n.to_bytes(length, "big")

class DssSigScheme:
    def __init__(self, key: Union[Any, Any], order: Any) -> None:
        self._key = key
        self._order = order

        self._order_bits = self._order.size_in_bits()
        self._order_bytes = (self._order_bits - 1) // 8 + 1

    def sign(self, msg_hash) -> bytes:
        nonce = self._compute_nonce()
        z = int.from_bytes(msg_hash.digest()[:self._order_bytes], byteorder="big")
        sig_pair = self._key._sign(z, nonce)
        output = b"".join([long_to_bytes(x, self._order_bytes) for x in sig_pair])
        return output

class FipsEcDsaSigScheme(DssSigScheme):
    def __init__(self, key: Any) -> None:
        order = key._curve.order
        super().__init__(key, order)
        self._randfunc = None

    def _compute_nonce(self):
        n = int(self._key._curve.order)
        return secrets.randbelow(n - 1) + 1