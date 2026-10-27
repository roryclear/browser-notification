from __future__ import annotations
from typing import Optional, Union
from ECC import DerOctetString

__all__ = ["wrap", "unwrap", "UnwrappedKey"]

def bytes_to_long(s: Union[bytes, bytearray, memoryview]) -> int: return int.from_bytes(s, "big")

class DerObject:
    def __init__(self) -> None: pass

    def _decodeLen(self, s: BytesIO_EOF) -> int:
        length = s.read_byte()
        if length > 127:
            encoded_length = s.read(length & 0x7F)
            length = bytes_to_long(encoded_length)
        return length

    def decode(self, der_encoded: bytes):
        s = BytesIO_EOF(der_encoded)
        self._decodeFromStream(s)
        return self

    def _decodeFromStream(self, s: BytesIO_EOF):
        s.read_byte()
        length = self._decodeLen(s)
        self.payload = s.read(length)

class BytesIO_EOF:
    def __init__(self, initial_bytes: bytes) -> None:
        self._buffer = initial_bytes
        self._index = 0
        self._bookmark: Optional[int] = None

    def set_bookmark(self) -> None: self._bookmark = self._index

    def data_since_bookmark(self) -> bytes: return self._buffer[self._bookmark : self._index]

    def remaining_data(self) -> int: return len(self._buffer) - self._index

    def read(self, length: int) -> bytes:
        new_index = self._index + length
        result = self._buffer[self._index : new_index]
        self._index = new_index
        return result

    def read_byte(self) -> int: return self.read(1)[0]

def decode_seq(seq, der_encoded):
    result = DerObject.decode(seq, der_encoded)
    return result


class DerSequence(DerObject):
    def __init__(self):
        DerObject.__init__(self)

    def _decodeFromStream(self, s: BytesIO_EOF) -> None:
        self._seq = []
        DerObject._decodeFromStream(self, s)
        p = BytesIO_EOF(self.payload)
        while p.remaining_data() > 0:
            p.set_bookmark()
            der = DerObject()
            der._decodeFromStream(p)
            self._seq.append(p.data_since_bookmark())
                
def unwrap(p8_private_key: bytes):
    pk_info = DerSequence().decode(p8_private_key)
    algo = DerSequence().decode(pk_info._seq[1])
    private_key = DerOctetString().decode(pk_info._seq[2]).payload
    return (private_key, algo._seq[1])