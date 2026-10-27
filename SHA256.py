from __future__ import annotations
import hashlib


class SHA256Hash:
    def __init__(self, data=None):
        self._hash = hashlib.sha256()
        if data: self.update(data)

    def update(self, data): self._hash.update(data)

    def digest(self) -> bytes: return self._hash.digest()

    def copy(self) -> SHA256Hash:
        clone = SHA256Hash()
        clone._hash = self._hash.copy()
        return clone