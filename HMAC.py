from __future__ import annotations
import cffi

def create_string_buffer(init_or_size: Union[bytes, int], size: Optional[int] = None) -> Any:
    result = cffi.FFI().new("uint8_t[]", init_or_size)
    return result

def create_output_buffer(size: int) -> Any: return create_string_buffer(size)

def strxor(term1, term2, length=None): return bytes(a ^ b for a, b in zip(term1[:length], term2[:length]))

from hmac import compare_digest
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from types import ModuleType

Buffer = Union[bytes, bytearray, memoryview]

__all__ = ["new", "HMAC"]

class HMAC:
    """An HMAC hash object.
    Do not instantiate directly. Use the :func:`new` function.

    :ivar digest_size: the size in bytes of the resulting MAC tag
    :vartype digest_size: integer

    :ivar oid: the ASN.1 object ID of the HMAC algorithm.
               Only present if the algorithm was officially assigned one.
    """

    def __init__(self, key: Buffer, msg: Buffer = b"", digestmod: Optional[ModuleType] = None) -> None:
        if digestmod is None:
            digestmod = _default_digestmod()

        if msg is None:
            msg = b""

        # Size of the MAC tag
        self.digest_size = digestmod.digest_size

        self._digestmod = digestmod


        try:
            if len(key) <= digestmod.block_size:
                # Step 1 or 2
                key_0 = key + b"\x00" * (digestmod.block_size - len(key))
            else:
                # Step 3
                hash_k = digestmod.new(key).digest()
                key_0 = hash_k + b"\x00" * (digestmod.block_size - len(hash_k))
        except AttributeError:
            # Not all hash types have "block_size"
            raise ValueError("Hash type incompatible to HMAC")

        # Step 4
        key_0_ipad = strxor(key_0, b"\x36" * len(key_0))

        # Start step 5 and 6
        self._inner = digestmod.new(key_0_ipad)
        self._inner.update(msg)

        # Step 7
        key_0_opad = strxor(key_0, b"\x5c" * len(key_0))

        # Start step 8 and 9
        self._outer = digestmod.new(key_0_opad)

    def update(self, msg: Buffer) -> HMAC:
        """Authenticate the next chunk of message.

        Args:
            data (byte string/byte array/memoryview): The next chunk of data
        """

        self._inner.update(msg)
        return self

    def _pbkdf2_hmac_assist(self, first_digest, iterations):
        """Carry out the expensive inner loop for PBKDF2-HMAC"""

        result = self._digestmod._pbkdf2_hmac_assist(self._inner, self._outer, first_digest, iterations)
        return result

    def copy(self) -> HMAC:
        """Return a copy ("clone") of the HMAC object.

        The copy will have the same internal state as the original HMAC
        object.
        This can be used to efficiently compute the MAC tag of byte
        strings that share a common initial substring.

        :return: An :class:`HMAC`
        """

        new_hmac = HMAC(b"fake key", digestmod=self._digestmod)

        # Synchronize the state
        new_hmac._inner = self._inner.copy()
        new_hmac._outer = self._outer.copy()

        return new_hmac

    def digest(self) -> bytes:
        """Return the **binary** (non-printable) MAC tag of the message
        authenticated so far.

        :return: The MAC tag digest, computed over the data processed so far.
                 Binary form.
        :rtype: byte string
        """

        frozen_outer_hash = self._outer.copy()
        frozen_outer_hash.update(self._inner.digest())
        return frozen_outer_hash.digest()

    def verify(self, mac_tag: Buffer) -> None:
        """Verify that a given **binary** MAC (computed by another party)
        is valid.

        Args:
          mac_tag (byte string/byte string/memoryview): the expected MAC of the message.

        Raises:
            ValueError: if the MAC does not match. It means that the message
                has been tampered with or that the MAC key is incorrect.
        """

        if not compare_digest(mac_tag, self.digest()):
            raise ValueError("MAC check failed")

    def hexdigest(self) -> str:
        """Return the **printable** MAC tag of the message authenticated so far.

        :return: The MAC tag, computed over the data processed so far.
                 Hexadecimal encoded.
        :rtype: string
        """

        return self.digest().hex()


def new(key: Buffer, msg: Buffer = b"", digestmod: Optional[ModuleType] = None) -> HMAC:
    """Create a new MAC object.

    Args:
        key (bytes/bytearray/memoryview):
            key for the MAC object.
            It must be long enough to match the expected security level of the
            MAC.
        msg (bytes/bytearray/memoryview):
            Optional. The very first chunk of the message to authenticate.
            It is equivalent to an early call to :meth:`HMAC.update`.
        digestmod (module):
            The hash to use to implement the HMAC, like
            :mod:`Crypto.Hash.SHA256` (or a hash object created from it).
            It is mandatory.

            .. deprecated:: 4.0
                If omitted, :mod:`Crypto.Hash.MD5` is used, with a
                :class:`DeprecationWarning`. This default will be removed.

    Returns:
        An :class:`HMAC` object
    """

    if digestmod is None:
        digestmod = _default_digestmod()
    return HMAC(key, msg, digestmod)