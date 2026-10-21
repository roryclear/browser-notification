from __future__ import annotations
import hashlib
from typing import Optional, Union


class SHA256Hash:
    """SHA-256 hash wrapper using Python's hashlib."""

    digest_size: int = 32
    block_size: int = 64
    oid: str = "2.16.840.1.101.3.4.2.1"

    def __init__(
        self,
        data: Optional[
            Union[bytes, bytearray, memoryview]
        ] = None,
    ) -> None:
        self._hash = hashlib.sha256()
        if data:
            self.update(data)

    def update(
        self,
        data: Union[bytes, bytearray, memoryview],
    ) -> None:
        self._hash.update(data)

    def digest(self) -> bytes:
        return self._hash.digest()

    def hexdigest(self) -> str:
        return self._hash.hexdigest()

    def copy(self) -> SHA256Hash:
        clone = SHA256Hash()
        clone._hash = self._hash.copy()
        return clone

    def new(
        self,
        data: Optional[
            Union[bytes, bytearray, memoryview]
        ] = None,
    ) -> SHA256Hash:
        return SHA256Hash(data)


def new(
    data: Optional[Union[bytes, bytearray, memoryview]] = None,
) -> SHA256Hash:
    return SHA256Hash(data)


digest_size: int = SHA256Hash.digest_size
block_size: int = SHA256Hash.block_size