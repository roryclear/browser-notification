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
import os
import threading
import abc

import cffi
ffi: Any = cffi.FFI()


from Crypto.Util._raw_api import (
    c_uint8_ptr_len,
    create_string_buffer,
    load_pycryptodome_raw_lib,
)
from Crypto.Util._file_system import pycryptodome_filename

from importlib import machinery
extension_suffixes = machinery.EXTENSION_SUFFIXES

_declared: set = set()
_declared_lock = threading.Lock()
def load_lib(name: str, cdecl: str) -> Any:
    """Load a shared library and return a handle to it.

    @name,  either an absolute path or the name of a library
            in the system search path.

    @cdecl, the C function declarations.
    """

    if hasattr(ffi, "RTLD_DEEPBIND") and not os.getenv("PYCRYPTODOME_DISABLE_DEEPBIND"):
        lib = ffi.dlopen(name, ffi.RTLD_DEEPBIND)
    else:
        lib = ffi.dlopen(name)
    # Several libraries can export the same functions (for instance,
    # a portable and an optimized build of the same code), but
    # cffi rejects a second declaration of a function.
    with _declared_lock:
        if cdecl not in _declared:
            ffi.cdef(cdecl)
            _declared.add(cdecl)
    return lib

class _VoidPointer:
    @abc.abstractmethod
    def get(self) -> Any:
        """Return the memory location we point to"""
        return

    @abc.abstractmethod
    def address_of(self) -> Any:
        """Return a raw pointer to this pointer"""
        return

class VoidPointer_cffi(_VoidPointer):
    """Model a newly allocated pointer to void"""

    def __init__(self):
        self._pp = ffi.new("void *[1]")

    def get(self):
        return self._pp[0]

    def address_of(self):
        return self._pp

def VoidPointer() -> _VoidPointer:
    return VoidPointer_cffi()

def load_pycryptodome_raw_lib(name: str, cdecl: str) -> Any:
    """Load a shared library and return a handle to it.

    @name,  the name of the library expressed as a PyCryptodome module,
            for instance Crypto.Cipher._raw_cbc.

    @cdecl, the C function declarations.
    """

    split = name.split(".")
    dir_comps, basename = split[:-1], split[-1]
    attempts = []
    for ext in extension_suffixes:
        try:
            filename = basename + ext
            full_name = pycryptodome_filename(dir_comps, filename)
            if not os.path.isfile(full_name):
                attempts.append("Not found '%s'" % filename)
                continue
            return load_lib(full_name, cdecl)
        except OSError as exp:
            attempts.append("Cannot load '%s': %s" % (filename, str(exp)))
    raise OSError("Cannot load native module '%s': %s" % (name, ", ".join(attempts)))

def get_raw_buffer(buf: Any) -> bytes: return ffi.buffer(buf)[:]

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