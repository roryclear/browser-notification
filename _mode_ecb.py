from typing import Any, Optional, Union
import cffi
from Crypto.Util._raw_api import load_pycryptodome_raw_lib

def create_string_buffer(init_or_size: Union[bytes, int], size: Optional[int] = None) -> Any:
    result = cffi.FFI().new("uint8_t[]", init_or_size)
    return result

def create_output_buffer(size: int) -> Any: return create_string_buffer(size)

def get_raw_buffer(buf: Any) -> bytes: return cffi.FFI().buffer(buf)[:]

class VoidPointer:
    def __init__(self): self._pp = cffi.FFI().new("void *[1]")
    def get(self): return self._pp[0]
    def address_of(self): return self._pp

class SmartPointer:
    def __init__(self, raw_pointer: Any, destructor: Any) -> None:
        self._raw_pointer = raw_pointer
        self._destructor = destructor

    def get(self) -> Any: return self._raw_pointer
    def release(self) -> Any: pass

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
        self._state = SmartPointer(state.get(), raw_ecb_lib.ECB_stop_operation)

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