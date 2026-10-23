from __future__ import annotations

from Crypto.Util._raw_api import load_pycryptodome_raw_lib
from _mode_ecb import create_output_buffer
import cffi

class c_uint8_ptr_out:
    def __init__(self, data) -> None:
        self._data = data
        self._copy =None

    def __enter__(self): return self._data
    def __exit__(self, exc_type, exc_value, traceback) -> None: pass


_raw_strxor = load_pycryptodome_raw_lib(
    "Crypto.Util._strxor",
    """
                    void strxor(const uint8_t *in1,
                                const uint8_t *in2,
                                uint8_t *out, size_t len);
                    void strxor_c(const uint8_t *in,
                                  uint8_t c,
                                  uint8_t *out,
                                  size_t len);
                    """,
)


import warnings
from binascii import unhexlify
from hmac import compare_digest
from typing import TYPE_CHECKING, Optional, Union

def strxor(
    term1: Buffer, term2: Buffer, output: Optional[Union[bytearray, memoryview]] = None
) -> Optional[bytes]:
    """From two byte strings of equal length,
    create a third one which is the byte-by-byte XOR of the two.

    Args:
      term1 (bytes/bytearray/memoryview):
        The first byte string to XOR.
      term2 (bytes/bytearray/memoryview):
        The second byte string to XOR.
      output (bytearray/memoryview):
        The location where the result will be written to.
        It must have the same length as ``term1`` and ``term2``.
        If ``None``, the result is returned.
    :Return:
        If ``output`` is ``None``, a new byte string with the result.
        Otherwise ``None``.

    .. note::
        ``term1`` and ``term2`` must have the same length.
    """

    if len(term1) != len(term2):
        raise ValueError("Only byte strings of equal length can be xored")

    result = create_output_buffer(len(term1))

    with c_uint8_ptr_out(result) as result_ptr:
        term1_ptr, term1_len = term1, len(term1)
        term2_ptr, _ = term2, len(term2)
        _raw_strxor.strxor(term1_ptr, term2_ptr, result_ptr, term1_len)

    return cffi.FFI().buffer(result)[:]

if TYPE_CHECKING:
    from types import ModuleType

Buffer = Union[bytes, bytearray, memoryview]

__all__ = ["new", "HMAC"]

_hash2hmac_oid = {
    "1.3.14.3.2.26": "1.2.840.113549.2.7",  # SHA-1
    "2.16.840.1.101.3.4.2.4": "1.2.840.113549.2.8",  # SHA-224
    "2.16.840.1.101.3.4.2.1": "1.2.840.113549.2.9",  # SHA-256
    "2.16.840.1.101.3.4.2.2": "1.2.840.113549.2.10",  # SHA-384
    "2.16.840.1.101.3.4.2.3": "1.2.840.113549.2.11",  # SHA-512
    "2.16.840.1.101.3.4.2.5": "1.2.840.113549.2.12",  # SHA-512_224
    "2.16.840.1.101.3.4.2.6": "1.2.840.113549.2.13",  # SHA-512_256
    "2.16.840.1.101.3.4.2.7": "2.16.840.1.101.3.4.2.13",  # SHA-3 224
    "2.16.840.1.101.3.4.2.8": "2.16.840.1.101.3.4.2.14",  # SHA-3 256
    "2.16.840.1.101.3.4.2.9": "2.16.840.1.101.3.4.2.15",  # SHA-3 384
    "2.16.840.1.101.3.4.2.10": "2.16.840.1.101.3.4.2.16",  # SHA-3 512
}

_hmac2hash_oid = {v: k for k, v in _hash2hmac_oid.items()}


def _default_digestmod() -> ModuleType:
    """Return MD5, the deprecated default hash, with a warning
    for the caller of :func:`new` (or of the :class:`HMAC` class)."""

    warnings.warn(
        "HMAC without 'digestmod' uses MD5, but this default is deprecated "
        "and will be removed: pass the hash explicitly (for instance, digestmod=SHA256)",
        DeprecationWarning,
        stacklevel=3,
    )
    from Crypto.Hash import MD5

    return MD5


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

        # Hash OID --> HMAC OID
        try:
            self.oid = _hash2hmac_oid[digestmod.oid]
        except (KeyError, AttributeError):
            pass

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