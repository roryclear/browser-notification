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

from ECC import bytes_to_long

from collections import namedtuple

class _GHASH:
    def __init__(self, subkey, ghash_c, threads=1):
        self.ghash_c = ghash_c
        self._threads = threads

        self._exp_key = VoidPointer()
        ghash_c.ghash_expand(subkey, self._exp_key.address_of())
        self._exp_key = SmartPointer(self._exp_key.get())
        self._last_y = create_string_buffer(16)

    def update(self, block_data):
        block_data = cffi.FFI().from_buffer("uint8_t[]", block_data)
        block_data_ptr, block_data_len = block_data, len(block_data)
        self.ghash_c.ghash(
            self._last_y,
            block_data_ptr,
            block_data_len,
            self._last_y,
            self._exp_key.get(),
        )
        return self

    def digest(self): return get_raw_buffer(self._last_y)

class GcmMode:
    def __init__(
        self,
        factory: Any,
        key: Any,
        nonce: Any,
        mac_len: int,
        cipher_params: dict,
        ghash_c: Any,
        threads: int = 1,
    ) -> None:
        self.block_size = factory.block_size
        self.nonce = bytes(nonce)
        self._factory = factory
        self._key = bytes(key)
        self._tag: Optional[bytes] = None  # Cache for MAC tag

        self._mac_len = mac_len
        self._no_more_assoc_data = False
        self._auth_len = 0
        self._msg_len = 0
        hash_subkey = factory.new(key, self._factory.MODE_ECB, **cipher_params).encrypt(b"\x00" * 16)

        # Step 2 - Compute J0
        if len(self.nonce) == 12:
            j0 = self.nonce + b"\x00\x00\x00\x01"

        # Step 3 - Prepare GCTR cipher for encryption/decryption
        nonce_ctr = j0[:12]
        iv_ctr = (bytes_to_long(j0) + 1) & 0xFFFFFFFF
        self._cipher = factory.new(
            key,
            self._factory.MODE_CTR,
            initial_value=iv_ctr,
            nonce=nonce_ctr,
            threads=threads,
            **cipher_params,
        )
        self._signer = _GHASH(hash_subkey, ghash_c)
        self._tag_cipher = factory.new(key, self._factory.MODE_CTR, initial_value=j0, nonce=b"", **cipher_params)
        self._cache = b""


    def _update(self, data):
        if len(self._cache) > 0:
            filler = min(16 - len(self._cache), len(data))
            self._cache += bytes(data[:filler])
            data = data[filler:]

            if len(self._cache) < 16:
                return

            self._signer.update(self._cache)
            self._cache = b""

        update_len = len(data) // 16 * 16
        self._cache = bytes(data[update_len:])
        if update_len > 0:
            if update_len < len(data):
                # Do not copy the data
                data = memoryview(data)[:update_len]
            self._signer.update(data)

    def _pad_cache_and_update(self):
        len_cache = len(self._cache)
        if len_cache > 0:
            self._update(b"\x00" * (16 - len_cache))

    def encrypt(
        self, plaintext, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        ciphertext = self._cipher.encrypt(plaintext, output=output)
        self._update(ciphertext if output is None else output)
        self._msg_len += len(plaintext)

        return ciphertext

    def digest(self) -> bytes:
        return self._compute_mac()

    def _compute_mac(self):
        # Step 5 in NIST SP 800-38D, Algorithm 4 - Compute S
        self._pad_cache_and_update()
        self._update(long_to_bytes(8 * self._auth_len, 8))
        self._update(long_to_bytes(8 * self._msg_len, 8))
        s_tag = self._signer.digest()

        # Step 6 - Compute T
        self._tag = self._tag_cipher.encrypt(s_tag)[: self._mac_len]

        return self._tag
    
    def encrypt_and_digest(
        self, plaintext, output: Optional[Union[bytearray, memoryview]] = None
    ) -> tuple[Optional[bytes], bytes]:
        return self.encrypt(plaintext, output=output), self.digest()

def _create_gcm_cipher(factory, **kwargs):
    key = kwargs.pop("key")
    nonce = kwargs.pop("nonce", None)
    mac_len = kwargs.pop("mac_len", 16)
    threads = kwargs.pop("threads", 1)

    # Not documented - only used for testing
    use_clmul = kwargs.pop("use_clmul", True)
    ghash_c = _ghash_portable

    return GcmMode(factory, key, nonce, mac_len, kwargs, ghash_c, threads)

_ghash_api = """
    int ghash_portable(uint8_t y_out[16],
                    const uint8_t block_data[],
                    size_t len,
                    const uint8_t y_in[16],
                    const void *exp_key);
    int ghash_expand_portable(const uint8_t h[16],
                           void **ghash_tables);
    int ghash_destroy_portable(void *ghash_tables);
    int ghash_at_portable(uint8_t y_out[16],
                       const uint8_t block_data[],
                       size_t offset,
                       size_t len,
                       const uint8_t y_in[16],
                       const void *exp_key);
    int ghash_combine_portable(uint8_t y_out[16],
                            const uint8_t y_in[16],
                            size_t n_blocks,
                            const uint8_t g[16],
                            const void *exp_key);
"""

def _get_ghash_portable():
    lib = load_pycryptodome_raw_lib("Crypto.Hash._ghash_portable", _ghash_api)
    funcs = ("ghash", "ghash_expand", "ghash_destroy", "ghash_at", "ghash_combine")
    GHASH_Imp = namedtuple("_GHash_Imp", funcs)
    imp_funcs = [getattr(lib, x + "_" + "portable") for x in funcs]
    params = dict(zip(funcs, imp_funcs))
    return GHASH_Imp(**params)

_ghash_portable = _get_ghash_portable()

def _create_gcm_cipher(factory, **kwargs):
    key = kwargs.pop("key")
    nonce = kwargs.pop("nonce", None)
    mac_len = kwargs.pop("mac_len", 16)
    threads = kwargs.pop("threads", 1)
    ghash_c = _ghash_portable
    return GcmMode(factory, key, nonce, mac_len, kwargs, ghash_c, threads)

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
        self._state = SmartPointer(block_cipher.get())

    def encrypt(
        self, plaintext, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        ciphertext = create_output_buffer(len(plaintext))
        with ciphertext as ciphertext_ptr:
            plaintext_ptr, plaintext_len = plaintext, len(plaintext)
            raw_ecb_lib.ECB_encrypt(
                self._state.get(), plaintext_ptr, ciphertext_ptr, plaintext_len
            )
        return get_raw_buffer(ciphertext)

from ECC import long_to_bytes
from Crypto.Cipher._mode_ctr import raw_ctr_lib

class CtrMode:
    def __init__(
        self,
        block_cipher: SmartPointer,
        initial_counter_block: Any,
        prefix_len: int,
        counter_len: int,
        little_endian: bool,
    ) -> None:
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
        
    def encrypt(
        self, plaintext, output: Optional[Union[bytearray, memoryview]] = None
    ) -> Optional[bytes]:
        return self._process(plaintext, output, "encrypting")


    def _process(
        self, data, output: Optional[Union[bytearray, memoryview]], what: str
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
        return raw_ctr_lib.CTR_encrypt(self._state.get(), in_ptr, out_ptr, data_len)

    @staticmethod
    def _check(result: int, what: str) -> None: pass

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

_raw_aes_lib = load_pycryptodome_raw_lib("Crypto.Cipher._raw_aes", _cproto)

def _create_base_cipher(dict_parameters):
    key = dict_parameters.pop("key")
    start_operation = _raw_aes_lib.AES_start_operation

    cipher = VoidPointer()
    key_ptr, key_len = key, len(key)
    start_operation(key_ptr, key_len, cipher.address_of())
    return SmartPointer(cipher.get())

def new(key: Any, mode: int, *args: Any, **kwargs: Any) -> Any:
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)

# Size of a data block (in bytes)
block_size: int = 16
# Size of a key (in bytes)
key_size: tuple[int, int, int] = (16, 24, 32)