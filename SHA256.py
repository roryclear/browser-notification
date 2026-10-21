#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================


from __future__ import annotations

from typing import Optional, Union, Any


from Crypto.Util._raw_api import (
    VoidPointer,
    c_uint8_ptr_len,
    create_string_buffer,
    get_raw_buffer,
    load_pycryptodome_raw_lib,
)
class SmartPointer:
    """Class to hold a non-managed piece of memory"""

    def __init__(self, raw_pointer: Any, destructor: Any) -> None:
        self._raw_pointer = raw_pointer
        self._destructor = destructor

    def get(self) -> Any:
        return self._raw_pointer

    def release(self) -> Any:
        rp, self._raw_pointer = self._raw_pointer, None
        return rp

    def __del__(self):
        try:
            if self._raw_pointer is not None:
                self._destructor(self._raw_pointer)
                self._raw_pointer = None
        except AttributeError:
            pass


_sha256_cdecl = """
                        int SHA256_init(void **shaState);
                        int SHA256_destroy(void *shaState);
                        int SHA256_update(void *hs,
                                          const uint8_t *buf,
                                          size_t len);
                        int SHA256_digest(const void *shaState,
                                          uint8_t *digest,
                                          size_t digest_size);
                        int SHA256_copy(const void *src, void *dst);
                        int SHA256_oneshot(const uint8_t *in,
                                        size_t len,
                                        uint8_t *digest,
                                        size_t digest_size);

                        int SHA256_pbkdf2_hmac_assist(const void *inner,
                                            const void *outer,
                                            const uint8_t *first_digest,
                                            uint8_t *final_digest,
                                            size_t iterations,
                                            size_t digest_size);
                        """

_raw_sha256_lib = load_pycryptodome_raw_lib("Crypto.Hash._SHA256", _sha256_cdecl)

class SHA256Hash:
    # The size of the resulting hash in bytes.
    digest_size: int = 32
    # The internal block size of the hash algorithm in bytes.
    block_size: int = 64
    # ASN.1 Object ID
    oid: str = "2.16.840.1.101.3.4.2.1"

    def __init__(self, data: Optional[Union[bytes, bytearray, memoryview]] = None) -> None:
        state = VoidPointer()
        _raw_sha256_lib.SHA256_init(state.address_of())
        self._state = SmartPointer(state.get(), _raw_sha256_lib.SHA256_destroy)
        if data: self.update(data)

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        data_ptr, data_len = c_uint8_ptr_len(data)
        _raw_sha256_lib.SHA256_update(self._state.get(), data_ptr, data_len)

    def digest(self) -> bytes:
        bfr = create_string_buffer(self.digest_size)
        _raw_sha256_lib.SHA256_digest(self._state.get(), bfr, self.digest_size)
        return get_raw_buffer(bfr)

    def copy(self) -> SHA256Hash:
        clone = SHA256Hash()
        _raw_sha256_lib.SHA256_copy(self._state.get(), clone._state.get())
        return clone

    def new(self, data: Optional[Union[bytes, bytearray, memoryview]] = None) -> SHA256Hash: return SHA256Hash(data)

def new(data: Optional[Union[bytes, bytearray, memoryview]] = None) -> SHA256Hash: return SHA256Hash().new(data)


digest_size: int = SHA256Hash.digest_size
block_size: int = SHA256Hash.block_size