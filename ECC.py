from __future__ import annotations
import re
from typing import (
    Any,
    Callable,
    Optional,
    TypedDict,
    Union,
    cast,
)
import random, secrets
import cffi
import operator
from abc import ABC
from Crypto.PublicKey._point import _curves
from Crypto.Util._raw_api import load_pycryptodome_raw_lib

_nat_cdecl = """
int nat_new(void **out, size_t nw);
void nat_free(void *x);
int nat_copy(void *out, const void *a);
int nat_from_bytes(void *out, const uint8_t *in, size_t len, int little_endian);
int nat_to_bytes(uint8_t *out, size_t len, const void *a, int little_endian);
int nat_from_uint64(void *out, uint64_t v);
int nat_bit_length(const void *a);
int nat_is_zero(const void *a);
int nat_is_odd(const void *a);
int nat_cmp(const void *a, const void *b);
int nat_get_bit(const void *a, size_t n);
int nat_add(void *out, const void *a, const void *b);
int nat_sub(void *out, const void *a, const void *b);
int nat_mul(void *out, const void *a, const void *b);
int nat_muladd(void *out, const void *c, const void *a, const void *b);
int nat_and(void *out, const void *a, const void *b);
int nat_or(void *out, const void *a, const void *b);
int nat_shl(void *out, const void *a, size_t k);
int nat_shr(void *out, const void *a, size_t k);
int nat_divmod(void *q, void *r, const void *a, const void *b);
int nat_mod_small(void *out, const void *a, uint64_t d);
int nat_mulmod(void *out, const void *a, const void *b, const void *m);
int nat_submod(void *out, const void *a, const void *b, const void *m);
int nat_powmod(void *out, const void *a, const void *e, size_t e_bits, const void *m);
int nat_invmod(void *out, const void *a, const void *m);
int nat_gcd(void *out, const void *a, const void *b);
int nat_jacobi(void *out, const void *a, const void *n, int negate);
int nat_isqrt(void *out, const void *a);
int nat_miller_rabin(void *out, const void *n, const void *base);
int nat_lucas(void *out, const void *n, uint64_t abs_d, int negative_d);
"""
_portable_lib = load_pycryptodome_raw_lib("Crypto.Math._nat", _nat_cdecl)
_lib = _portable_lib

null_pointer = cffi.FFI().NULL

def _new_nat(bits: int) -> SmartPointer:
    nw = max(1, (bits + 63) // 64)
    raw = VoidPointer()
    _lib.nat_new(raw.address_of(), nw)
    return SmartPointer(raw.get(), _lib.nat_free)


def create_string_buffer(init_or_size: Union[bytes, int], size: Optional[int] = None) -> Any:
    result = cffi.FFI().new("uint8_t[]", init_or_size)
    return result

def get_raw_buffer(buf: Any) -> bytes: return cffi.FFI().buffer(buf)[:]

def _encode_coordinate(value: Union[int, IntegerBase], length: int) -> bytes:
    encoded = long_to_bytes(int(value), length)
    return encoded

def bytes_to_long(s: Union[bytes, bytearray, memoryview]) -> int:
    return int.from_bytes(s, "big")

def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    n = operator.index(n)
    length = max((n.bit_length() + 7) // 8, 1)
    if blocksize > 0: length = ceil_div(length, blocksize) * blocksize
    return n.to_bytes(length, "big")

def _curve_context(curve: _Curve) -> Any:
    return null_pointer if curve.context is None else curve.context.get()

class IntegerBase(ABC):
    _public: bool = False

    def _is_public_with(self, term: Any) -> bool:
        return False

    @classmethod
    def random(
        cls,
        *,
        exact_bits: Optional[int] = None,
        max_bits: Optional[int] = None,
        randfunc=None,
    ) -> IntegerBase:
        bits = max_bits
        bytes_needed = ((bits - 1) // 8) + 1
        significant_bits_msb = 8 - (bytes_needed * 8 - bits)
        msb = secrets.token_bytes(1)[0]
        msb &= (1 << significant_bits_msb) - 1
        ret = cls.from_bytes(bytes([msb]) + secrets.token_bytes(bytes_needed - 1))
        return ret

    @classmethod
    def random_range(
        cls,
        *,
        min_inclusive: Optional[Union[IntegerBase, int]] = None,
        max_inclusive: Optional[Union[IntegerBase, int]] = None,
        max_exclusive: Optional[Union[IntegerBase, int]] = None,
        randfunc: Optional[RandFunc] = None,
    ) -> IntegerBase:
        max_inclusive = max_exclusive - 1

        norm_maximum = cls(max_inclusive) - min_inclusive
        bits_needed = norm_maximum.size_in_bits()

        while True:
            norm_candidate = cls.random(max_bits=bits_needed)
            if norm_candidate <= norm_maximum:
                return norm_candidate + min_inclusive


class IntegerNat(IntegerBase):
    """A natural number (0, 1, 2, ...), with constant-time arithmetic"""

    _p: SmartPointer
    _bits: int

    def __init__(self, value: Union[IntegerBase, int], _min_bits: int = 0, *, public: bool = False) -> None:
        self._public = public or (isinstance(value, IntegerBase) and value._public)
        value = int(value)
        nbytes = max(1, (value.bit_length() + 7) // 8)
        self._alloc(max(value.bit_length(), _min_bits))
        data = value.to_bytes(nbytes, "little")
        _lib.nat_from_bytes(self._p.get(), data, nbytes, 1)

    # Internal helpers
    def _alloc(self, bits: int) -> None:
        self._bits = max(1, bits)
        self._p = _new_nat(self._bits)

    @classmethod
    def _make(cls, bits: int) -> IntegerNat:
        """A new number equal to 0, with the given bound"""
        obj = cls.__new__(cls)
        obj._alloc(bits)
        return obj

    def _adopt(self, other: IntegerNat) -> IntegerNat:
        """Take the value, the bound and the public flag of another (temporary) number"""
        self._p = other._p
        self._bits = other._bits
        self._public = other._public
        return self

    @staticmethod
    def _conv(term: Any) -> IntegerNat:
        return IntegerNat(operator.index(term))

    def _nw(self) -> int:
        return max(1, (self._bits + 63) // 64)

    def _is_zero(self) -> bool:
        return bool(_lib.nat_is_zero(self._p.get()))


    def __int__(self) -> int:
        nbytes = 8 * self._nw()
        buf = create_string_buffer(nbytes)
        _lib.nat_to_bytes(buf, nbytes, self._p.get(), 1)
        return int.from_bytes(get_raw_buffer(buf), "little")

    def __index__(self) -> int:
        return int(self)

    def __str__(self) -> str:
        return str(int(self))

    def __repr__(self) -> str:
        return "Integer(%s)" % str(self)

    def to_bytes(self, block_size: Optional[int] = 0, byteorder: str = "big") -> bytes:
        buf = create_string_buffer(block_size)
        _lib.nat_to_bytes(buf, block_size, self._p.get(), int(byteorder == "little"))
        return get_raw_buffer(buf)

    @classmethod
    def from_bytes(
        cls,
        byte_string: Union[bytes, bytearray, memoryview],
        byteorder: str = "big",
        _min_bits: int = 0,
        *,
        public: bool = False,
    ) -> IntegerNat:
        length = len(byte_string)
        result = cls._make(max(8 * length, _min_bits))
        result._public = public
        _lib.nat_from_bytes(
            result._p.get(), c_uint8_ptr(byte_string), length, int(byteorder == "little")
            )
        return result

    # Relations

    def _cmp(self, term: Any) -> int:
        if isinstance(term, int) and term < 0:
            return 1
        # Keep a reference to the converted term until the C call is done
        other = self._conv(term)
        return _lib.nat_cmp(self._p.get(), other._p.get())


    def __le__(self, term: IntLike) -> bool:
        return self._cmp(term) <= 0



    # Arithmetic operations

    def __add__(self, term: IntLike) -> IntegerNat:
        public = self._is_public_with(term)
        try:
            term = self._conv(term)
        except TypeError:
            return NotImplemented
        result = IntegerNat._make(max(self._bits, term._bits) + 1)
        _lib.nat_add(result._p.get(), self._p.get(), term._p.get())
        result._public = public
        return result

    __radd__ = __add__

    def __sub__(self, term: IntLike) -> IntegerNat:
        public = self._is_public_with(term)
        try:
            term = self._conv(term)
        except TypeError:
            return NotImplemented
        result = IntegerNat._make(max(self._bits, term._bits))
        _lib.nat_sub(result._p.get(), self._p.get(), term._p.get())
        result._public = public
        return result


    def __mul__(self, factor: IntLike) -> IntegerNat:
        public = self._is_public_with(factor)
        try:
            factor = self._conv(factor)
        except TypeError:
            return NotImplemented
        result = IntegerNat._make(self._bits + factor._bits)
        _lib.nat_mul(result._p.get(), self._p.get(), factor._p.get())
        result._public = public
        return result

    __rmul__ = __mul__

    def __mod__(self, divisor: IntLike) -> IntegerNat:
        public = self._is_public_with(divisor)
        divisor = self._check_modulus(divisor)
        result = IntegerNat._make(divisor._bits)
        _lib.nat_divmod(null_pointer, result._p.get(), self._p.get(), divisor._p.get())
        result._public = public
        return result

    @staticmethod
    def _check_modulus(
        modulus: IntLike, name: str = "Modulus", zero_error: type[Exception] = ZeroDivisionError
    ) -> IntegerNat:
        """Convert a modulus into an IntegerNat.

        ValueError if it is negative, zero_error if it is zero (only that fact leaks).
        """
        if isinstance(modulus, int) and modulus < 0:
            raise ValueError("%s must be positive" % name)
        modulus = IntegerNat._conv(modulus)
        if modulus._is_zero():
            raise zero_error("%s cannot be zero" % name)
        return modulus

    def size_in_bits(self) -> int:
        return max(1, _lib.nat_bit_length(self._p.get()))

    def inplace_inverse(self, modulus: IntLike) -> IntegerNat:
        public = self._is_public_with(modulus)
        modulus = self._check_modulus(modulus)
        result = IntegerNat._make(modulus._bits)
        _lib.nat_invmod(result._p.get(), self._p.get(), modulus._p.get())
        result._public = public
        return self._adopt(result)

    def inverse(self, modulus: IntLike) -> IntegerNat:
        result = IntegerNat(self)
        return result.inplace_inverse(modulus)

def c_uint8_ptr(data: Union[bytes, memoryview, bytearray]) -> Any: return cffi.FFI().from_buffer("uint8_t[]", data)

def ceil_div(n: int, d: int) -> int:
    r, q = divmod(n, d)
    if (n != 0) and (q != 0): r += 1
    return r

def _encode_scalar(scalar: Union[int, IntegerBase], min_length: int) -> bytes: return long_to_bytes(scalar)

def _copy_point(point):
    copy = point.__class__.__new__(point.__class__)
    copy._curve = point._curve
    copy.curve = point.curve
    copy._point = _clone_raw_point(point._curve, point)
    return copy

def _clone_raw_point(curve, point) -> SmartPointer:
    raw_point = VoidPointer()
    curve.rawlib.clone(raw_point.address_of(), point._point.get())
    return SmartPointer(raw_point.get(), curve.rawlib.free_point)

class StrongRandom:
    def __init__(self, rng: Optional[Any] = None, randfunc: Optional[Callable] = None) -> None:
        if randfunc is None and rng is None:
            self._randfunc = None
        elif randfunc is not None and rng is None:
            self._randfunc = randfunc
        elif randfunc is None and rng is not None:
            self._randfunc = rng.read
        else:
            raise ValueError("Cannot specify both 'rng' and 'randfunc'")

    def getrandbits(self, k: int) -> int:
        mask = (1 << k) - 1
        return mask & bytes_to_long(secrets.token_bytes(ceil_div(k, 8)))

class c_uint8_ptr_out:
    def __init__(self, data: Any) -> None:
        self._data = data
        self._copy: Any = None

    def __enter__(self) -> Any: return c_uint8_ptr(self._data)
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None: pass

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

RNG = Callable[[int], bytes]
Int = Union[int, Any]

class EccPoint:
    def __init__(self, x: Union[int, Any], y: Union[int, Any], curve: Optional[str] = "p256") -> None:
        self._curve = _curves[curve]
        self.curve = "NIST P-256"

        modulus_bytes = self.size_in_bytes()

        xb = _encode_coordinate(x, modulus_bytes)
        yb = _encode_coordinate(y, modulus_bytes)
        # todo why
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        xb = long_to_bytes(bytes_to_long(xb) % p, modulus_bytes)
        yb = long_to_bytes(bytes_to_long(yb) % p, modulus_bytes)

        new_point = self._curve.rawlib.new_point
        free_func = self._curve.rawlib.free_point

        raw_point = VoidPointer()
        context = _curve_context(self._curve)
        new_point(raw_point.address_of(), xb, yb, modulus_bytes, context)
        self._point = SmartPointer(raw_point.get(), free_func)

    def copy(self) -> EccPoint:return _copy_point(self)

    @property
    def x(self) -> int:
        return self.xy[0]

    @property
    def y(self) -> int:
        return self.xy[1]

    @property
    def xy(self) -> tuple[int, int]:
        xb, yb = self._get_xy_bytes()
        return (bytes_to_long(xb), bytes_to_long(yb))

    @property
    def _x(self):
        return self._xy[0]

    @property
    def _y(self):
        return self._xy[1]

    @property
    def _xy(self):
        xb, yb = self._get_xy_bytes()
        return (IntegerNat.from_bytes(xb), IntegerNat.from_bytes(yb))

    def _get_xy_bytes(self) -> tuple[bytearray, bytearray]:
        modulus_bytes = self.size_in_bytes()
        xb = bytearray(modulus_bytes)
        yb = bytearray(modulus_bytes)
        get_xy = self._curve.rawlib.get_xy
        with c_uint8_ptr_out(xb) as xb_ptr, c_uint8_ptr_out(yb) as yb_ptr:
            result = get_xy(xb_ptr, yb_ptr, modulus_bytes, self._point.get())
        if result:
            raise ValueError("Error %d while encoding an EC point" % result)
        return xb, yb

    def size_in_bytes(self) -> int:
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self) -> int:
        """Size of each coordinate, in bits."""
        return self._curve.modulus_bits



    def __imul__(self, scalar: int) -> EccPoint:
        # A public scalar: no blinding, and only as many bits as needed
        public_func = getattr(self._curve.rawlib, "scalar_public", None)
        if public_func is not None and isinstance(scalar, IntegerBase) and scalar._public:
            sb = scalar.to_bytes()
            sb_ptr, sb_len = sb, len(sb)
            result = public_func(self._point.get(), sb_ptr, sb_len)
        else:
            sb = _encode_scalar(scalar, self.size_in_bytes())
            sb_ptr, sb_len = sb, len(sb)
            result = self._curve.rawlib.scalar(
                self._point.get(), sb_ptr, sb_len, StrongRandom().getrandbits(64)
            )
        if result:
            raise ValueError("Error %d during scalar multiplication" % result)
        return self

    def __mul__(self, scalar: int) -> EccPoint:
        """Return a new point, the scalar product of this one"""

        np = self.copy()
        np *= scalar
        return np


class BytesIO_EOF:
    def __init__(self, initial_bytes: bytes) -> None:
        self._buffer = initial_bytes
        self._index = 0
        self._bookmark: Optional[int] = None

    def set_bookmark(self) -> None:
        self._bookmark = self._index

    def data_since_bookmark(self) -> bytes:
        assert self._bookmark is not None
        return self._buffer[self._bookmark : self._index]

    def remaining_data(self) -> int:
        return len(self._buffer) - self._index

    def read(self, length: int) -> bytes:
        new_index = self._index + length
        result = self._buffer[self._index : new_index]
        self._index = new_index
        return result

    def read_byte(self) -> int:
        return self.read(1)[0]

class DerObject:
    def __init__(
        self,
        asn1Id: Optional[Union[int, bytes]] = None,
        payload: bytes = b"",
        implicit: Optional[Union[int, bytes]] = None,
        constructed: bool = False,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        self._tag_octet: Optional[int]
        # The tag octet will be read in with ``decode``
        self._tag_octet = None
        return

    def _decodeLen(self, s: BytesIO_EOF) -> int:
        length = s.read_byte()
        return length

    def decode(self: _DerObjectT, der_encoded: bytes, strict: bool = False) -> _DerObjectT:
        s = BytesIO_EOF(der_encoded)
        self._decodeFromStream(s, strict)
        return self

    def _decodeFromStream(self, s: BytesIO_EOF, strict: bool) -> None:
        idOctet = s.read_byte()
        self._tag_octet = idOctet
        length = self._decodeLen(s)
        self.payload = s.read(length)


class DerObjectId(DerObject):
    def __init__(
        self,
        value: str = "",
        implicit: Optional[Union[int, bytes]] = None,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        DerObject.__init__(self, 0x06, b"", implicit, False, explicit)
        self.value = value

    def decode(self, der_encoded: bytes, strict: bool = False) -> DerObjectId: return DerObject.decode(self, der_encoded, strict)

    def _decodeFromStream(self, s, strict):
        DerObject._decodeFromStream(self, s, strict)

        # Derive self.value from self.payload
        p = BytesIO_EOF(self.payload)

        subcomps = []
        v = 0
        while p.remaining_data():
            c = p.read_byte()
            v = (v << 7) + (c & 0x7F)
            if not (c & 0x80):
                subcomps.append(v)
                v = 0

        if len(subcomps) == 0:
            raise ValueError("Empty payload")

        if subcomps[0] < 40:
            subcomps[:1] = [0, subcomps[0]]
        elif subcomps[0] < 80:
            subcomps[:1] = [1, subcomps[0] - 40]
        else:
            subcomps[:1] = [2, subcomps[0] - 80]

        self.value = ".".join([str(x) for x in subcomps])

    def _convertTag(self, tag: Union[int, bytes]) -> int:
        """Check if *tag* is a real DER tag (5 bits).
        Convert it from a character to number if necessary.
        """
        if isinstance(tag, (bytes, bytearray)) and len(tag) == 1:
            tag = tag[0]
        # Ensure that tag is a low tag
        if not (isinstance(tag, int) and 0 <= tag < 0x1F):
            raise ValueError("Wrong DER tag")
        return tag

class DerObject:
    """Base class for defining a single DER object.

    This class should never be directly instantiated.
    """

    def __init__(
        self,
        asn1Id: Optional[Union[int, bytes]] = None,
        payload: bytes = b"",
        implicit: Optional[Union[int, bytes]] = None,
        constructed: bool = False,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        self._tag_octet: Optional[int]
        if asn1Id is None:
            # The tag octet will be read in with ``decode``
            self._tag_octet = None
            return
        asn1Id = self._convertTag(asn1Id)

        self.payload = payload

        # In a BER/DER identifier octet:
        # * bits 4-0 contain the tag value
        # * bit 5 is set if the type is 'constructed'
        #   and unset if 'primitive'
        # * bits 7-6 depend on the encoding class
        #
        # Class        | Bit 7, Bit 6
        # ----------------------------------
        # universal    |   0      0
        # application  |   0      1
        # context-spec |   1      0 (default for IMPLICIT/EXPLICIT)
        # private      |   1      1
        #

        constructed_bit = 0x20 if constructed else 0x00


        if implicit is not None:
            # IMPLICIT tag overrides asn1Id
            self._tag_octet = 0x80 | constructed_bit | self._convertTag(implicit)
        elif explicit is not None:
            # 'constructed bit' is always asserted for an EXPLICIT tag
            self._tag_octet = 0x80 | 0x20 | self._convertTag(explicit)
            self._inner_tag_octet = constructed_bit | asn1Id
        else:
            # Neither IMPLICIT nor EXPLICIT
            self._tag_octet = constructed_bit | asn1Id

    def _convertTag(self, tag: Union[int, bytes]) -> int:
        return tag

    def _decodeLen(self, s: BytesIO_EOF) -> int:
        length = s.read_byte()
        return length

    def decode(self: _DerObjectT, der_encoded: bytes, strict: bool = False) -> _DerObjectT:
        s = BytesIO_EOF(der_encoded)
        self._decodeFromStream(s, strict)
        return self

    def _decodeFromStream(self, s: BytesIO_EOF, strict: bool) -> None:
        """Decode a complete DER element from a file."""

        idOctet = s.read_byte()
        if self._tag_octet is not None:
            if idOctet != self._tag_octet:
                raise ValueError("Unexpected DER tag")
        else:
            self._tag_octet = idOctet
        length = self._decodeLen(s)
        self.payload = s.read(length)
        if hasattr(self, "_inner_tag_octet"):
            p = BytesIO_EOF(self.payload)
            inner_octet = p.read_byte()
            if inner_octet != self._inner_tag_octet:
                raise ValueError("Unexpected internal DER tag")
            length = self._decodeLen(p)
            self.payload = p.read(length)


class DerOctetString(DerObject):
    def __init__(self, value: bytes = b"", implicit: Optional[Union[int, bytes]] = None) -> None:
        DerObject.__init__(self, 0x04, value, implicit, False)

class DerBitString(DerObject):
    def __init__(
        self,
        value: Union[bytes, DerObject] = b"",
        implicit: Optional[Union[int, bytes]] = None,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        DerObject.__init__(self, 0x03, b"", implicit, False, explicit)
        self.value = value

    def _decodeFromStream(self, s, strict):
        DerObject._decodeFromStream(self, s, strict)
        # Fill-up self.value
        self.value = b""
        # Remove padding count byte
        if self.payload:
            self.value = self.payload[1:]


class DerSequence(DerObject):
    def __init__(
        self,
        startSeq = None,
        implicit: Optional[int] = None,
        explicit: Optional[int] = None,
    ) -> None:
        DerObject.__init__(self, 0x10, b"", implicit, True, explicit)
        self._seq: list[Any]
        if startSeq is None:
            self._seq = []
        else:
            self._seq = cast(list[Any], startSeq)


    def __getitem__(self, n: Union[int, slice]) -> Any: return self._seq[n]

    def __len__(self) -> int: return len(self._seq)

    def decode(
        self,
        der_encoded: bytes,
        strict: bool = False,
        nr_elements: Optional[Union[int, Any[int]]] = None,
        only_ints_expected: bool = False,
    ) -> DerSequence:
        self._nr_elements = nr_elements
        result = DerObject.decode(self, der_encoded, strict=strict)
        return result

    def _decodeFromStream(self, s: Any, strict: bool) -> None:
        self._seq = []

        # Fill up self.payload
        DerObject._decodeFromStream(self, s, strict)

        # Add one item at a time to self.seq, by scanning self.payload
        p = BytesIO_EOF(self.payload)
        while p.remaining_data() > 0:
            p.set_bookmark()

            der = DerObject()
            der._decodeFromStream(p, strict)

            # Parse INTEGERs differently
            if der._tag_octet != 0x02:
                self._seq.append(p.data_since_bookmark())
            else:
                data = p.data_since_bookmark()
                self._seq.append(1)


class ConstructParams(TypedDict, total=False):
    curve: str
    d: Union[int, Any]
    seed: bytes
    point_x: Optional[Union[int, Any]]
    point_y: Optional[Union[int, Any]]

class EccKey:
    def __init__(
        self,
        *,
        curve: Optional[str] = None,
        d: Optional[Union[int, Any]] = None,
        seed: Optional[bytes] = None,
        point: Optional[Union[Any, Any]] = None,
    ) -> None:
        curve_name = curve
        # Which of these attributes are set depends on the type of key
        self._d: Any = cast(Any, d)
        self._seed: Any = cast(Any, seed)
        self._point: Any = cast(Any, point)
        if curve_name is None and self._point:
            curve_name = self._point.curve

        self._curve = _curves[curve_name]
        self.curve = self._curve.canonical

    # ECDSA
    def _sign(self, z, k):
        assert 0 < k < self._curve.order

        order = self._curve.order
        blind = IntegerNat.random_range(min_inclusive=1, max_exclusive=order)

        blind_d = self._d * blind
        inv_blind_k = (blind * k).inverse(order)

        r = (self._curve.G * k)._x % order
        s = inv_blind_k * (blind * z + blind_d * r) % order
        return (r, s)

    @property
    def pointQ(self) -> Any:
        if self._point is None:
            self._point = self._curve.G * self._d
        return self._point

    def public_key(self) -> EccKey:
        return EccKey(curve=self._curve.canonical, point=self.pointQ)

    def _export_SEC1(self, compress):
        modulus_bytes = self.pointQ.size_in_bytes()

        x, y = self.pointQ._xy
        if compress:
            if y.is_odd():
                first_byte = b"\x03"
            else:
                first_byte = b"\x02"
            public_key = first_byte + x.to_bytes(modulus_bytes)
        else:
            public_key = b"\x04" + x.to_bytes(modulus_bytes) + y.to_bytes(modulus_bytes)
        return public_key

    def export_key(
        self,
        *,
        format: str,
        passphrase: Optional[Union[bytes, str]] = None,
        use_pkcs8: bool = True,
        protection: Optional[str] = None,
        compress: bool = False,
        prot_params: Optional[ProtParams] = None,
        randfunc: Optional[RNG] = None,
        threads: int = 1,
    ) -> Union[str, bytes]:
        ext_format = format
        private_only = {
            "passphrase": passphrase,
            "use_pkcs8": None if use_pkcs8 is True else use_pkcs8,
            "protection": protection,
            "prot_params": prot_params,
            "randfunc": randfunc,
            "threads": None if threads == 1 else threads,
        }
        unexpected = {k: v for k, v in private_only.items() if v is not None}
        if unexpected:
            raise ValueError("Unexpected parameters: '%s'" % unexpected)
        if ext_format == "PEM":
            return self._export_public_pem(compress)
        elif ext_format == "DER":
            return self._export_subjectPublicKeyInfo(compress)
        elif ext_format == "SEC1":
            return self._export_SEC1(compress)
        elif ext_format == "raw":
            if self._curve.is_edwards:
                return self._export_eddsa_public()
            elif self._curve.is_montgomery:
                return self._export_montgomery_public()
            else:
                return self._export_SEC1(compress)
        else:
            return self._export_openssh(compress)


def generate(*, curve) -> EccKey:
    curve_name = curve
    curve_info = _curves[curve_name]
    d = random.randrange(1, curve_info.order)
    new_key = EccKey(curve=curve_name, d=d)

    return new_key

def construct(**kwargs: Unpack[ConstructParams]) -> EccKey:
    params = cast(dict[str, Any], kwargs)

    curve_name = params["curve"]
    point_x = params.pop("point_x", None)
    point_y = params.pop("point_y", None)

    if None not in (point_x, point_y):
        params["point"] = EccPoint(point_x, point_y, curve_name)
    new_key = EccKey(**params)

    return new_key


def _import_public_der(ec_point, curve_oid=None, curve_name=None):
    for _curve_name, curve in _curves.items():
        if curve_oid and curve.oid == curve_oid:
            break
        if curve_name == _curve_name:
            break

    modulus_bytes = curve.p.size_in_bytes()
    x = int.from_bytes(ec_point[1 : modulus_bytes + 1], byteorder="big")
    y = int.from_bytes(ec_point[modulus_bytes + 1 :], byteorder="big")
    return construct(curve=_curve_name, point_x=x, point_y=y)

def _import_rfc5915_der(
    encoded: bytes, curve_oid: Optional[str] = None
) -> EccKey:
    ec_private_key = DerSequence().decode(encoded, nr_elements=(2, 3, 4))
    scalar_bytes = DerOctetString().decode(ec_private_key[1]).payload
    next_element = 2

    for curve_name, curve in _curves.items():
        if curve.oid == curve_oid:
            break

    # Try to decode 'publicKey'
    point_x = point_y = None
    if next_element < len(ec_private_key):
        public_key_enc = DerBitString(explicit=1).decode(ec_private_key[next_element]).value
        public_key = _import_public_der(public_key_enc, curve_oid=curve_oid)
        point_x = public_key.pointQ.x
        point_y = public_key.pointQ.y
        next_element += 1

    d = int.from_bytes(scalar_bytes, byteorder="big")
    return construct(curve=curve_name, d=d, point_x=point_x, point_y=point_y)


def _import_pkcs8(encoded, passphrase, max_iteration_count=None, threads=1, max_memory=None):
    import PKCS8
    unwrapped = PKCS8.unwrap(encoded, passphrase, max_iteration_count, threads=threads, max_memory=max_memory)
    _, private_key, params = unwrapped
    curve_oid = DerObjectId().decode(params).value
    key = _import_rfc5915_der(private_key, curve_oid)
    return key

def _import_der(encoded, passphrase, max_iteration_count=None, threads=1, max_memory=None):
    return _import_pkcs8(encoded, passphrase, max_iteration_count, threads, max_memory)

def import_key(
    encoded: Union[bytes, str],
    passphrase: Optional[Union[str, bytes]] = None,
    curve_name: Optional[str] = None,
    *,
    max_iteration_count: Optional[int] = None,
    threads: int = 1,
    max_memory: Optional[int] = None,
) -> EccKey:
    import PEM

    if encoded.startswith(b"-----"):
        text_encoded = encoded.decode("latin-1")
        ecparams_start = "-----BEGIN EC PARAMETERS-----"
        ecparams_end = "-----END EC PARAMETERS-----"
        text_encoded = re.sub(ecparams_start + ".*?" + ecparams_end, "", text_encoded, flags=re.DOTALL)
        
        der_encoded, _, _ = PEM.decode(text_encoded, passphrase)
        result = _import_der(der_encoded, passphrase, max_iteration_count, threads, max_memory)
        return result

    # SEC1
    if len(encoded) > 0 and encoded[0] in (0x02, 0x03, 0x04):
        return _import_public_der(encoded, curve_name=curve_name)
