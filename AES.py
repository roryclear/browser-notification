import sys
from typing import Any, Literal, Union, Optional
from ECC import SmartPointer
from Crypto.Util._raw_api import load_pycryptodome_raw_lib

import cffi

def create_string_buffer(init_or_size: Union[bytes, int], size: Optional[int] = None) -> Any:
    result = cffi.FFI().new("uint8_t[]", init_or_size)
    return result

def create_output_buffer(size: int) -> Any: return create_string_buffer(size)

def get_raw_buffer(buf: Any) -> bytes: return cffi.FFI().buffer(buf)[:]

class VoidPointer:
    def __init__(self): self._pp = cffi.FFI().new("void *[1]")
    def get(self): return self._pp[0]
    def address_of(self): return self._pp

Buffer = Union[bytes, bytearray, memoryview]

raw_ecb_lib = load_pycryptodome_raw_lib(
    "Crypto.Cipher._raw_ecb",
    """
                    int ECB_start_operation(void *cipher,
                                            void **pResult);
                    int ECB_encrypt(void *ecbState,
                                    const uint8_t *in,
                                    uint8_t *out,
                                    size_t data_len);
                    int ECB_decrypt(void *ecbState,
                                    const uint8_t *in,
                                    uint8_t *out,
                                    size_t data_len);
                    int ECB_stop_operation(void *state);
                    """,
)


class EcbMode:
    def __init__(self, block_cipher: Any) -> None:
        self.block_size = block_cipher.block_size
        state = VoidPointer()
        raw_ecb_lib.ECB_start_operation(block_cipher.get(), state.address_of())
        self._state = SmartPointer(state.get())

    def encrypt(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        ciphertext = create_output_buffer(len(plaintext))
        with ciphertext as ciphertext_ptr:
            plaintext_ptr, plaintext_len = plaintext, len(plaintext)
            raw_ecb_lib.ECB_encrypt(
                self._state.get(), plaintext_ptr, ciphertext_ptr, plaintext_len
            )
        return get_raw_buffer(ciphertext)

def _create_ecb_cipher(factory, **kwargs):
    cipher_state = factory._create_base_cipher(kwargs)
    cipher_state.block_size = factory.block_size
    return EcbMode(cipher_state)

def _create_cipher(factory, key, mode, **kwargs):
    if mode == 1:
        res = _create_ecb_cipher(factory, key=key)

    elif mode == 6:
        from Crypto.Cipher._mode_ctr import _create_ctr_cipher
        res = _create_ctr_cipher(factory, key=key, initial_value=kwargs["initial_value"], nonce=kwargs["nonce"])

    elif mode == 11:
        from Crypto.Cipher._mode_gcm import _create_gcm_cipher
        res = _create_gcm_cipher(factory, key=key, nonce=kwargs["nonce"])

    return res

class VoidPointer:
    def __init__(self): self._pp = cffi.FFI().new("void *[1]")
    def get(self): return self._pp[0]
    def address_of(self): return self._pp

backend: str = "cffi"

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
    return SmartPointer(cipher.get())

def new(key: Buffer, mode: int, *args: Any, **kwargs: Any) -> Any:
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)

# Size of a data block (in bytes)
block_size: int = 16
# Size of a key (in bytes)
key_size: tuple[int, int, int] = (16, 24, 32)