from __future__ import annotations
from typing import Optional, Union
from ECC import DerObjectId, DerOctetString

__all__ = ["wrap", "unwrap", "UnwrappedKey"]

def bytes_to_long(s: Union[bytes, bytearray, memoryview]) -> int: return int.from_bytes(s, "big")

class DerObject:
    def __init__(
        self,
        asn1Id: Optional[Union[int, bytes]] = None,
        payload: bytes = b"",
        constructed: bool = False,
        explicit: Optional[Union[int, bytes]] = None,
        value = 0
    ) -> None:
        self.value = value
        self._tag_octet: Optional[int]
        if asn1Id is None:
            self._tag_octet = None
            return

        self.payload = payload
        constructed_bit = 0x20 if constructed else 0x00
        self._tag_octet = constructed_bit | asn1Id

    def _decodeLen(self, s: BytesIO_EOF) -> int:
        length = s.read_byte()
        if length > 127:
            encoded_length = s.read(length & 0x7F)
            length = bytes_to_long(encoded_length)
        return length

    def decode(self, der_encoded: bytes, strict: bool = False):
        s = BytesIO_EOF(der_encoded)
        self._decodeFromStream(s, strict)
        return self

    def _decodeFromStream(self, s: BytesIO_EOF, strict: bool) -> None:
        idOctet = s.read_byte()
        self._tag_octet = idOctet
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

class DerSequence(DerObject):
    def __init__(self):
        DerObject.__init__(self)
    
    def decode(self, der_encoded: bytes, strict: bool = False, nr_elements=None):
        self._nr_elements = nr_elements
        result = DerObject.decode(self, der_encoded, strict=strict)
        return result

    def _decodeFromStream(self, s: BytesIO_EOF, strict: bool) -> None:
        self._seq = []
        DerObject._decodeFromStream(self, s, strict)
        p = BytesIO_EOF(self.payload)
        while p.remaining_data() > 0:
            p.set_bookmark()

            der = DerObject()
            der._decodeFromStream(p, strict)

            # Parse INTEGERs differently
            if der._tag_octet != 0x02:
                self._seq.append(p.data_since_bookmark())
            else:
                derInt = DerObject()
                data = p.data_since_bookmark()
                derInt.decode(data, strict=strict)
                self._seq.append(derInt.value)

class UnwrappedKey(tuple[str, bytes, Optional[bytes]]):
    public_key: Optional[bytes]

    @classmethod
    def _create(cls, oid: str, private_key: bytes, params: Optional[bytes],public_key: Optional[bytes]) -> UnwrappedKey:
        result = cls((oid, private_key, params))
        result.public_key = public_key
        return result

def unwrap(p8_private_key: bytes):
    pk_info = DerSequence().decode(p8_private_key, nr_elements=(2, 3, 4, 5))
    algo = DerSequence().decode(pk_info._seq[1], nr_elements=(1, 2))
    algo_oid = DerObjectId().decode(algo._seq[0]).value
    algo_params = None if len(algo._seq) == 1 else algo._seq[1]
    private_key = DerOctetString().decode(pk_info._seq[2]).payload
    public_key = None


    return UnwrappedKey._create(algo_oid, private_key, algo_params, public_key)