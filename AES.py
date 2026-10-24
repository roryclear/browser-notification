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

def _create_gcm_cipher(factory, **kwargs):
    key = kwargs.pop("key")
    nonce = kwargs.pop("nonce", None)
    mac_len = kwargs.pop("mac_len", 16)
    threads = kwargs.pop("threads", 1)

    lib = load_pycryptodome_raw_lib("Crypto.Hash._ghash_portable", _ghash_api)
    funcs = ("ghash", "ghash_expand", "ghash_destroy", "ghash_at", "ghash_combine")
    GHASH_Imp = namedtuple("_GHash_Imp", funcs)
    imp_funcs = [getattr(lib, x + "_" + "portable") for x in funcs]
    params = dict(zip(funcs, imp_funcs))
    ghash_c = GHASH_Imp(**params)
    return GcmMode(factory, key, nonce, mac_len, kwargs, ghash_c, threads)

class VoidPointer:
    def __init__(self): self._pp = cffi.FFI().new("void *[1]")
    def get(self): return self._pp[0]
    def address_of(self): return self._pp

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

_M2  = [_gmul(x, 2)  for x in range(256)]
_M3  = [_gmul(x, 3)  for x in range(256)]
_M9  = [_gmul(x, 9)  for x in range(256)]
_M11 = [_gmul(x, 11) for x in range(256)]
_M13 = [_gmul(x, 13) for x in range(256)]
_M14 = [_gmul(x, 14) for x in range(256)]

Te0 = [( _M2[s]<<24)|(s<<16)|(s<<8)| _M3[s] for s in SBOX]
Te1 = [( _M3[s]<<24)|(_M2[s]<<16)|(s<<8)| s     for s in SBOX]
Te2 = [( s<<24)    |(_M3[s]<<16)|(_M2[s]<<8)| s for s in SBOX]
Te3 = [( s<<24)    |(s<<16)    |(_M3[s]<<8)|_M2[s] for s in SBOX]
Te4 = [( s<<24)|(s<<16)|(s<<8)| s for s in SBOX]

RCON = [0x01000000,0x02000000,0x04000000,0x08000000,
        0x10000000,0x20000000,0x40000000,0x80000000,
        0x1B000000,0x36000000]

def _ld32(b, o=0):
    return (b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3]

def _st32(b, v, o=0):
    b[o]   = (v >> 24) & 0xff
    b[o+1] = (v >> 16) & 0xff
    b[o+2] = (v >>  8) & 0xff
    b[o+3] =  v        & 0xff


def key_setup_enc(key, key_bits):
    rk = [0] * 60
    i = 0
    off = 0
    rk[0] = _ld32(key, 0);  rk[1] = _ld32(key, 4)
    rk[2] = _ld32(key, 8);  rk[3] = _ld32(key, 12)

    if key_bits == 128:
        while True:
            t = rk[off+3]
            rk[off+4] = (rk[off+0]
                         ^ (Te4[(t>>16)&0xff] & 0xff000000)
                         ^ (Te4[(t>> 8)&0xff] & 0x00ff0000)
                         ^ (Te4[ t     &0xff] & 0x0000ff00)
                         ^ (Te4[(t>>24)&0xff] & 0x000000ff)
                         ^ RCON[i])
            rk[off+5] = rk[off+1] ^ rk[off+4]
            rk[off+6] = rk[off+2] ^ rk[off+5]
            rk[off+7] = rk[off+3] ^ rk[off+6]
            i += 1
            if i == 10:
                return rk, 10
            off += 4

    rk[4] = _ld32(key, 16); rk[5] = _ld32(key, 20)
    if key_bits == 192:
        while True:
            t = rk[off+5]
            rk[off+6] = (rk[off+0]
                         ^ (Te4[(t>>16)&0xff] & 0xff000000)
                         ^ (Te4[(t>> 8)&0xff] & 0x00ff0000)
                         ^ (Te4[ t     &0xff] & 0x0000ff00)
                         ^ (Te4[(t>>24)&0xff] & 0x000000ff)
                         ^ RCON[i])
            rk[off+7]  = rk[off+1] ^ rk[off+6]
            rk[off+8]  = rk[off+2] ^ rk[off+7]
            rk[off+9]  = rk[off+3] ^ rk[off+8]
            i += 1
            if i == 8:
                return rk, 12
            rk[off+10] = rk[off+4] ^ rk[off+9]
            rk[off+11] = rk[off+5] ^ rk[off+10]
            off += 6

    rk[6] = _ld32(key, 24); rk[7] = _ld32(key, 28)
    if key_bits == 256:
        while True:
            t = rk[off+7]
            rk[off+8] = (rk[off+0]
                         ^ (Te4[(t>>16)&0xff] & 0xff000000)
                         ^ (Te4[(t>> 8)&0xff] & 0x00ff0000)
                         ^ (Te4[ t     &0xff] & 0x0000ff00)
                         ^ (Te4[(t>>24)&0xff] & 0x000000ff)
                         ^ RCON[i])
            rk[off+9]  = rk[off+1] ^ rk[off+8]
            rk[off+10] = rk[off+2] ^ rk[off+9]
            rk[off+11] = rk[off+3] ^ rk[off+10]
            i += 1
            if i == 7:
                return rk, 14
            t = rk[off+11]
            rk[off+12] = (rk[off+4]
                          ^ (Te4[(t>>24)&0xff] & 0xff000000)
                          ^ (Te4[(t>>16)&0xff] & 0x00ff0000)
                          ^ (Te4[(t>> 8)&0xff] & 0x0000ff00)
                          ^ (Te4[ t     &0xff] & 0x000000ff))
            rk[off+13] = rk[off+5] ^ rk[off+12]
            rk[off+14] = rk[off+6] ^ rk[off+13]
            rk[off+15] = rk[off+7] ^ rk[off+14]
            off += 8
    return rk, 0


def rijndael_encrypt(rk, nr, pt):
    s0 = _ld32(pt, 0)  ^ rk[0]
    s1 = _ld32(pt, 4)  ^ rk[1]
    s2 = _ld32(pt, 8)  ^ rk[2]
    s3 = _ld32(pt, 12) ^ rk[3]

    off = 0
    for _ in range(nr - 1):
        t0 = Te0[(s0>>24)&0xff] ^ Te1[(s1>>16)&0xff] ^ Te2[(s2>>8)&0xff] ^ Te3[s3&0xff] ^ rk[off+4]
        t1 = Te0[(s1>>24)&0xff] ^ Te1[(s2>>16)&0xff] ^ Te2[(s3>>8)&0xff] ^ Te3[s0&0xff] ^ rk[off+5]
        t2 = Te0[(s2>>24)&0xff] ^ Te1[(s3>>16)&0xff] ^ Te2[(s0>>8)&0xff] ^ Te3[s1&0xff] ^ rk[off+6]
        t3 = Te0[(s3>>24)&0xff] ^ Te1[(s0>>16)&0xff] ^ Te2[(s1>>8)&0xff] ^ Te3[s2&0xff] ^ rk[off+7]
        s0, s1, s2, s3 = t0, t1, t2, t3
        off += 4

    off = nr << 2
    ct = bytearray(16)
    _st32(ct, (Te4[(s0>>24)&0xff] & 0xff000000)
             ^ (Te4[(s1>>16)&0xff] & 0x00ff0000)
             ^ (Te4[(s2>> 8)&0xff] & 0x0000ff00)
             ^ (Te4[ s3     &0xff] & 0x000000ff)
             ^ rk[off], 0)
    _st32(ct, (Te4[(s1>>24)&0xff] & 0xff000000)
             ^ (Te4[(s2>>16)&0xff] & 0x00ff0000)
             ^ (Te4[(s3>> 8)&0xff] & 0x0000ff00)
             ^ (Te4[ s0     &0xff] & 0x000000ff)
             ^ rk[off+1], 4)
    _st32(ct, (Te4[(s2>>24)&0xff] & 0xff000000)
             ^ (Te4[(s3>>16)&0xff] & 0x00ff0000)
             ^ (Te4[(s0>> 8)&0xff] & 0x0000ff00)
             ^ (Te4[ s1     &0xff] & 0x000000ff)
             ^ rk[off+2], 8)
    _st32(ct, (Te4[(s3>>24)&0xff] & 0xff000000)
             ^ (Te4[(s0>>16)&0xff] & 0x00ff0000)
             ^ (Te4[(s1>> 8)&0xff] & 0x0000ff00)
             ^ (Te4[ s2     &0xff] & 0x000000ff)
             ^ rk[off+3], 12)
    return ct


class BlockState:
    """Pure-Python equivalent of the C `block_state` struct."""
    def __init__(self, key):
        self.rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self.ek, _ = key_setup_enc(key, len(key) * 8)

    def encrypt_block(self, block16):
        return bytes(rijndael_encrypt(self.ek, self.rounds, block16))

    def encrypt(self, data):
        out = bytearray()
        for i in range(0, len(data), 16):
            out += rijndael_encrypt(self.ek, self.rounds, data[i:i+16])
        return bytes(out)

class EcbMode:
    def __init__(self, key: bytes) -> None:
        self.block_size = 16
        self._state = BlockState(key)

    def encrypt(self, plaintext, output=None):
        data = bytes(plaintext)
        if len(data) % 16:
            raise ValueError("ECB plaintext length must be a multiple of 16")

        result = self._state.encrypt(data)

        if output is not None:
            output[:] = result           # honour caller's buffer
            return None
        return result

from ECC import long_to_bytes

class CTRRepeatedKeyStreamError(Exception):
    """Raised when the CTR keystream would wrap around (NIST SP 800-38A limit)."""


class CtrMode:
    def __init__(
        self,
        block_cipher,                 # BlockState (from the AES answer)
        initial_counter_block,
        prefix_len: int,
        counter_len: int,
        little_endian: bool,
    ) -> None:
        if prefix_len + counter_len > len(initial_counter_block):
            raise ValueError("prefix_len + counter_len exceeds block length")

        self._cipher      = block_cipher
        self.block_size   = len(initial_counter_block)
        self._counter     = bytearray(initial_counter_block)
        self._prefix_len  = prefix_len
        self._counter_len = counter_len
        self._little_endian = little_endian

        self._keystream   = None   # bytes: current block's keystream (when _used > 0)
        self._used        = 0      # bytes consumed from current block

        self._bytes_processed = 0
        self._max_bytes = (1 << (8 * counter_len)) * self.block_size

    # ------------------------------------------------------------------ helpers

    def _increment_counter(self, counter: bytearray) -> None:
        p, c = self._prefix_len, self._counter_len
        if self._little_endian:
            for k in range(c):
                counter[p + k] = (counter[p + k] + 1) & 0xff
                if counter[p + k]:
                    return
        else:
            for k in range(c):
                i = p + c - 1 - k
                counter[i] = (counter[i] + 1) & 0xff
                if counter[i]:
                    return

    def _check(self, n: int) -> None:
        if self._bytes_processed + n > self._max_bytes:
            raise CTRRepeatedKeyStreamError(
                "keystream would repeat (limit %d bytes)" % self._max_bytes
            )

    def _consume(self, n: int) -> bytes:
        """Advance state by n bytes; return the keystream slice."""
        out = bytearray()
        rem = n
        while rem:
            if self._used == 0:
                self._keystream = self._cipher.encrypt_block(bytes(self._counter))
                self._increment_counter(self._counter)
            take = min(rem, self.block_size - self._used)
            out += self._keystream[self._used : self._used + take]
            self._used += take
            rem -= take
            if self._used == self.block_size:
                self._used, self._keystream = 0, None
        self._bytes_processed += n
        return bytes(out)

    def _peek(self, offset: int, n: int) -> bytes:
        """Compute n keystream bytes at `offset` from current position; do NOT advance."""
        out = bytearray()
        rem = n

        # 1) Portion that lies inside the current partial block
        if self._used > 0:
            avail = self.block_size - self._used
            take = min(rem, max(0, avail - offset))
            if take:
                start = self._used + offset
                out += self._keystream[start : start + take]
                rem -= take
                offset += take
            if rem:
                offset -= avail                     # now relative to next block start

        # 2) Remainder: blocks starting at self._counter
        if rem:
            counter = bytearray(self._counter)
            skip_blocks = offset // self.block_size
            in_block    = offset %  self.block_size
            for _ in range(skip_blocks):
                self._increment_counter(counter)

            while rem:
                ks = self._cipher.encrypt_block(bytes(counter))
                self._increment_counter(counter)
                take = min(rem, self.block_size - in_block)
                out += ks[in_block : in_block + take]
                rem -= take
                in_block = 0

        return bytes(out)

    # ----------------------------------------------------------------- public

    def encrypt(self, plaintext, output=None):
        data = bytes(plaintext)
        self._check(len(data))
        ks = self._consume(len(data))
        result = bytes(a ^ b for a, b in zip(data, ks))
        if output is not None:
            output[:] = result
            return None
        return result

    def decrypt(self, ciphertext, output=None):          # CTR is symmetric
        return self.encrypt(ciphertext, output=output)

    def encrypt_at(self, plaintext, offset, output=None):
        """Peek at `offset` from current position; state is unchanged."""
        data = bytes(plaintext)
        if self._bytes_processed + offset + len(data) > self._max_bytes:
            raise CTRRepeatedKeyStreamError(
                "keystream would repeat (limit %d bytes)" % self._max_bytes
            )
        ks = self._peek(offset, len(data))
        result = bytes(a ^ b for a, b in zip(data, ks))
        if output is not None:
            output[:] = result
            return None
        return result

    def skip(self, n: int) -> None:
        self._check(n)
        self._consume(n)                                  # discard keystream

    def check(self, n: int) -> bool:
        return self._bytes_processed + n <= self._max_bytes

def _create_ctr_cipher(factory, **kwargs):
    kwargs.pop("threads", None)                     # ignored
    key = kwargs.pop("key")

    cipher_state = BlockState(key)

    counter       = kwargs.pop("counter", None)
    nonce         = kwargs.pop("nonce", None)
    initial_value = kwargs.pop("initial_value", None)

    if counter is None:
        counter_len = factory.block_size - len(nonce)
        if initial_value is None:
            initial_value = 0
        if isinstance(initial_value, int):
            initial_counter_block = nonce + long_to_bytes(initial_value, counter_len)
        else:
            if len(initial_value) != counter_len:
                raise ValueError("Incorrect length for counter byte string")
            initial_counter_block = nonce + initial_value
        return CtrMode(cipher_state, initial_counter_block,
                       len(nonce), counter_len, False)

    # `counter` dict path (kept for API compatibility)
    _c = dict(counter)
    counter_len = _c.pop("counter_len")
    prefix      = _c.pop("prefix")
    suffix      = _c.pop("suffix")
    _c.pop("initial_value")                         # was ignored in the original
    little_endian = _c.pop("little_endian")

    zeros = b"\x00" * counter_len
    if not little_endian:
        zeros = zeros[::-1]
    initial_counter_block = prefix + zeros + suffix
    return CtrMode(cipher_state, initial_counter_block, len(prefix), counter_len, little_endian)


def _create_ecb_cipher(factory, **kwargs):
    return EcbMode(kwargs["key"])

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


def _create_base_cipher(dict_parameters):
    from_ = dict_parameters.pop("key")
    return BlockState(from_)          # pure-Python AES

def new(key: Any, mode: int, *args: Any, **kwargs: Any) -> Any:
    return _create_cipher(sys.modules[__name__], key, mode, *args, **kwargs)

# Size of a data block (in bytes)
block_size: int = 16
# Size of a key (in bytes)
key_size: tuple[int, int, int] = (16, 24, 32)