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
        implicit: Optional[Union[int, bytes]] = None,
        constructed: bool = False,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        self._tag_octet: Optional[int]
        if asn1Id is None:
            self._tag_octet = None
            return
        asn1Id = self._convertTag(asn1Id)

        self.payload = payload
        constructed_bit = 0x20 if constructed else 0x00
        self._tag_octet = constructed_bit | asn1Id

    def _convertTag(self, tag: Union[int, bytes]) -> int:
        return tag

    def _decodeLen(self, s: BytesIO_EOF) -> int:
        """Decode DER length octets from a file."""
        length = s.read_byte()
        if length > 127:
            encoded_length = s.read(length & 0x7F)
            length = bytes_to_long(encoded_length)
        return length

    def decode(self: _DerObjectT, der_encoded: bytes, strict: bool = False) -> _DerObjectT:
        s = BytesIO_EOF(der_encoded)
        self._decodeFromStream(s, strict)
        return self

    def _decodeFromStream(self, s: BytesIO_EOF, strict: bool) -> None:
        idOctet = s.read_byte()
        self._tag_octet = idOctet
        length = self._decodeLen(s)
        self.payload = s.read(length)

class DerInteger(DerObject):
    def __init__(
        self,
        value: int = 0,
        implicit: Optional[Union[int, bytes]] = None,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        DerObject.__init__(self, 0x02, b"", implicit, False, explicit)
        self.value = value


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
    def __init__(
        self,
        startSeq=None,
        implicit=None,
        explicit=None,
    ) -> None:
        DerObject.__init__(self, 0x10, b"", implicit, True, explicit)

    def __getitem__(self, n: Union[int, slice]) -> Any:
        return self._seq[n]

    def __len__(self) -> int: return len(self._seq)
    
    def decode(
        self,
        der_encoded: bytes,
        strict: bool = False,
        nr_elements: Optional[Union[int, Iterable[int]]] = None,
        only_ints_expected: bool = False,
    ) -> DerSequence:
        self._nr_elements = nr_elements
        result = DerObject.decode(self, der_encoded, strict=strict)

        if only_ints_expected and not self.hasOnlyInts():
            raise ValueError("Some members are not INTEGERs")

        return result

    def _decodeFromStream(self, s: BytesIO_EOF, strict: bool) -> None:
        """Decode a complete DER SEQUENCE from a file."""

        self._seq = []

        # Fill up self.payload
        DerObject._decodeFromStream(self, s, strict)

        # Add one item at a time to self.seq, by scanning self.payload
        p = BytesIO_EOF(self.payload)
        while p.remaining_data() > 0:
            p.set_bookmark()

            der = DerObject()
            der._decodeFromStream(p, strict)

            # Parse INTEGERs differently
            if der._tag_octet != 0x02:
                self._seq.append(p.data_since_bookmark())
            else:
                derInt = DerInteger()
                data = p.data_since_bookmark()
                derInt.decode(data, strict=strict)
                self._seq.append(derInt.value)

        ok = True
        if isinstance(self._nr_elements, int):
            ok = len(self._seq) == self._nr_elements
        elif self._nr_elements is not None:
            ok = len(self._seq) in self._nr_elements

        if not ok:
            raise ValueError("Unexpected number of members (%d) in the sequence" % len(self._seq))

#: Encryption scheme of a private key, when the ``protection`` is not specified
DEFAULT_PROTECTION = "PBKDF2WithHMAC-SHA256AndAES256-CBC"


class UnwrappedKey(tuple[str, bytes, Optional[bytes]]):
    public_key: Optional[bytes]

    @classmethod
    def _create(
        cls,
        oid: str,
        private_key: bytes,
        params: Optional[bytes],
        public_key: Optional[bytes],
    ) -> UnwrappedKey:
        result = cls((oid, private_key, params))
        result.public_key = public_key
        return result

def unwrap(
    p8_private_key: bytes,
    passphrase: Optional[Union[bytes, str]] = None,
    max_iteration_count: Optional[int] = None,
    *,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> UnwrappedKey:
    pk_info = DerSequence().decode(p8_private_key, nr_elements=(2, 3, 4, 5))
    algo = DerSequence().decode(pk_info[1], nr_elements=(1, 2))
    algo_oid = DerObjectId().decode(algo[0]).value
    algo_params = None if len(algo) == 1 else algo[1]
    private_key = DerOctetString().decode(pk_info[2]).payload
    public_key = None


    return UnwrappedKey._create(algo_oid, private_key, algo_params, public_key)