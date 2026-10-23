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

from ECC import long_to_bytes
from Crypto.Cipher._mode_ctr import threads_param, raw_ctr_lib
from Crypto.Cipher._state_machine import Method

class CtrMode:
    def __init__(
        self,
        block_cipher: SmartPointer,
        initial_counter_block: Buffer,
        prefix_len: int,
        counter_len: int,
        little_endian: bool,
        threads: int = 1,
    ) -> None:
        self._threads = threads_param(threads)

        if len(initial_counter_block) == prefix_len + counter_len:
            self.nonce = bytes(initial_counter_block[:prefix_len])

        state = VoidPointer()
        initial_counter_block_ptr, initial_counter_block_len = initial_counter_block, len(initial_counter_block)
        raw_ctr_lib.CTR_start_operation(
            block_cipher.get(),
            initial_counter_block_ptr,
            initial_counter_block_len,
            prefix_len,
            counter_len,
            little_endian,
            state.address_of(),
        )
        self._state = SmartPointer(state.get())

        self.block_size = len(initial_counter_block)
        self._next = [Method.ENCRYPT, Method.DECRYPT]
        
    def encrypt(
        self, plaintext: Buffer, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        self._next = [Method.ENCRYPT]
        return self._process(plaintext, output, "encrypting")


    def _process(
        self, data: Buffer, output: Optional[Union[bytearray, memoryview]], what: str
    ) -> Optional[bytes]:
        """Encrypt or decrypt (which are the same operation in CTR mode)"""

        if output is None:
            result_buffer = create_output_buffer(len(data))
        else:
            result_buffer = output

            if not is_writeable_buffer(output):
                raise TypeError("output must be a bytearray or a writeable memoryview")

            if len(data) != len(output):
                raise ValueError("output must have the same length as the input  (%d bytes)" % len(data))

        with result_buffer as result_ptr:
            data_ptr, data_len = data, len(data)
            # Check the lengths of the buffers that C code gets
            if len(result_ptr) != data_len:
                raise ValueError("output must have the same length as the input  (%d bytes)" % data_len)
            result = self._ctr(data_ptr, result_ptr, data_len)
        self._check(result, what)

        if output is None:
            return get_raw_buffer(result_buffer)
        else:
            return None

    def _ctr(self, in_ptr, out_ptr, data_len: int) -> int:
        if self._threads > 1:
            return _ctr_threaded(self._state.get(), in_ptr, out_ptr, data_len, self._threads)
        return raw_ctr_lib.CTR_encrypt(self._state.get(), in_ptr, out_ptr, data_len)

    @staticmethod
    def _check(result: int, what: str) -> None:
        if result:
            if result == 0x60002:
                raise MessageTooLongError("The counter has wrapped around in CTR mode")
            raise ValueError("Error %X while %s in CTR mode" % (result, what))

def _create_ctr_cipher(factory, **kwargs):
    threads = kwargs.pop("threads", 1)

    cipher_state = factory._create_base_cipher(kwargs)

    counter = kwargs.pop("counter", None)
    nonce = kwargs.pop("nonce", None)
    initial_value = kwargs.pop("initial_value", None)
    if counter is None:

        # What is not nonce is counter
        counter_len = factory.block_size - len(nonce)

        if initial_value is None:
            initial_value = 0

        if isinstance(initial_value, int):
            initial_counter_block = nonce + long_to_bytes(initial_value, counter_len)
        else:
            if len(initial_value) != counter_len:
                raise ValueError(
                    "Incorrect length for counter byte string (%d bytes, expected %d)"
                    % (len(initial_value), counter_len)
                )
            initial_counter_block = nonce + initial_value

        return CtrMode(
            cipher_state,
            initial_counter_block,
            len(nonce),  # prefix
            counter_len,
            False,  # little_endian
            threads,
        )

    # Crypto.Util.Counter is used

    # 'counter' used to be a callable object, but now it is
    # just a dictionary for backward compatibility.
    _counter = dict(counter)
    counter_len = _counter.pop("counter_len")
    prefix = _counter.pop("prefix")
    suffix = _counter.pop("suffix")
    initial_value = _counter.pop("initial_value")
    little_endian = _counter.pop("little_endian")

    # Compute initial counter block
    words = []
    words += [b"\x00"] * max(0, counter_len - len(words))
    if not little_endian:
        words.reverse()
    initial_counter_block = prefix + b"".join(words) + suffix
    return CtrMode(cipher_state, initial_counter_block, len(prefix), counter_len, little_endian, threads)

def _create_ecb_cipher(factory, **kwargs):
    cipher_state = factory._create_base_cipher(kwargs)
    cipher_state.block_size = factory.block_size
    return EcbMode(cipher_state)

def _create_cipher(factory, key, mode, **kwargs):
    if mode == 1:
        res = _create_ecb_cipher(factory, key=key)

    elif mode == 6:
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