#
#  PublicKey/PKCS8.py : PKCS#8 functions
#
# SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause


from __future__ import annotations

from typing import Optional, Union

from ECC import DerObjectId, DerOctetString

from Crypto.Util.asn1 import DerObject, BytesIO_EOF, DerInteger

__all__ = ["wrap", "unwrap", "UnwrappedKey"]


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