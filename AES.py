import sys
from typing import Any, Literal, Union

from Crypto.Cipher import _create_cipher
from Crypto.Util._raw_api import load_pycryptodome_raw_lib

import cffi


class VoidPointer:
    def __init__(self): self._pp = cffi.FFI().new("void *[1]")
    def get(self): return self._pp[0]
    def address_of(self): return self._pp

backend: str = "cffi"

class SmartPointer:
    def __init__(self, raw_pointer: Any, destructor: Any) -> None:
        self._raw_pointer = raw_pointer
        self._destructor = destructor

    def get(self) -> Any: return self._raw_pointer
    def release(self) -> Any: pass

Buffer = Union[bytes, bytearray, memoryview]

MODE_ECB: Literal[1] = 1  #: Electronic Code Book (:ref:`ecb_mode`)
MODE_CTR: Literal[6] = 6  #: Counter mode (:ref:`ctr_mode`)
MODE_GCM: Literal[11] = 11  #: Galois Counter Mode (:ref:`gcm_mode`)

_cproto = """
        int AES_start_operation(const uint8_t key[],
                                size_t key_len,
                                void **pResult);
        int AES_encrypt(const void *state,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t data_len);
        int AES_decrypt(const void *state,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t data_len);
        int AES_stop_operation(void *state);
        """

# Load portable AES
_raw_aes_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aes", _cproto)

def _create_base_cipher(dict_parameters):
    key = dict_parameters.pop("key")
    start_operation = _raw_aes_lib.AES_start_operation
    stop_operation = _raw_aes_lib.AES_stop_operation

    cipher = VoidPointer()
    key_ptr, key_len = key, len(key)
    start_operation(key_ptr, key_len, cipher.address_of())
    return SmartPointer(cipher.get(), stop_operation)

def new(key: Buffer, mode: int, *args: Any, **kwargs: Any) -> Any:
    kwargs["add_aes_modes"] = True
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)

# Size of a data block (in bytes)
block_size: int = 16
# Size of a key (in bytes)
key_size: tuple[int, int, int] = (16, 24, 32)