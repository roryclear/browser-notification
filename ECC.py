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
import operator
from abc import ABC
import re
from binascii import a2b_base64

def decode(pem_data: str) -> tuple[bytes, str, bool]:
    r = re.compile(r"\s*-----BEGIN (.*)-----\s+")
    m = r.match(pem_data)
    marker = m.group(1)
    lines = pem_data.replace(" ", "").split()
    data = a2b_base64("".join(lines[1:-1]))
    enc_flag = False

    return (data, marker, enc_flag)

def _py_new_point(xb: bytes, yb: bytes, curve: "_Curve") -> dict:
    p = int(curve.p)
    x = int.from_bytes(xb, "big") % p
    y = int.from_bytes(yb, "big") % p
    if x == 0 and y == 0: return {"x": 0, "y": 1, "z": 0}
    return {"x": x, "y": y, "z": 1}


def _py_clone_point(point: dict) -> dict: return {"x": point["x"], "y": point["y"], "z": point["z"]}

def _py_get_xy_bytes(point: dict, modulus_bytes: int, curve: "_Curve") -> tuple:
    p = int(curve.p)
    X, Y, Z = point["x"], point["y"], point["z"]
    if Z % p == 0: return bytearray(modulus_bytes), bytearray(modulus_bytes)
    Zinv = pow(Z, -1, p)
    x = (X * Zinv) % p
    y = (Y * Zinv) % p
    return (bytearray(x.to_bytes(modulus_bytes, "big")),
            bytearray(y.to_bytes(modulus_bytes, "big")))


def _affine_double(P, p: int, a: int = -3):
    if P is None:
        return None
    x, y = P
    if y % p == 0:
        return None
    lam = ((3 * x * x + a) * pow(2 * y, -1, p)) % p
    x3 = (lam * lam - 2 * x) % p
    y3 = (lam * (x - x3) - y) % p
    return (x3, y3)


def _affine_add(P, Q, p: int, a: int = -3):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        return _affine_double(P, p, a)
    lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _py_scalar_mul(point: dict, k: int, curve: "_Curve") -> dict:
    """Simple double-and-add (functionally equivalent, not constant-time)."""
    p = int(curve.p)
    if curve.order is not None:
        k = k % int(curve.order)
    if k == 0 or point["z"] % p == 0:
        return {"x": 0, "y": 1, "z": 0}

    Zinv = pow(point["z"], -1, p)
    ax = (point["x"] * Zinv) % p
    ay = (point["y"] * Zinv) % p

    result = None
    addend = (ax, ay)
    for bit in bin(k)[2:]:
        if result is not None:
            result = _affine_double(result, p)
        if bit == "1":
            result = _affine_add(result, addend, p)

    if result is None:
        return {"x": 0, "y": 1, "z": 0}
    return {"x": result[0], "y": result[1], "z": 1}

class _Curve:
    def __init__(self, p=None, order=None, Gx=None, Gy=None, modulus_bits=None, oid=None, canonical=None, rawlib=None):
        self.p = p
        self.order = order
        self.Gx = Gx
        self.Gy = Gy
        self.modulus_bits = modulus_bits
        self.oid = oid
        self.canonical = canonical
        self.rawlib = rawlib

def curve25519_curve():
    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED  # 2**255 - 19
    order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED


    curve25519 = _Curve(
        p=IntegerNat(p),
        order=IntegerNat(order),
        Gx=IntegerNat(9),
        Gy=None,
        modulus_bits=255,
        oid="1.3.101.110",  # RFC8410
        canonical="Curve25519",
        rawlib=None,
    )
    return curve25519


def curve448_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 2**448 - 2**224 - 1
    order = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3

    curve448 = _Curve(
        p=IntegerNat(p),
        order=IntegerNat(order),
        Gx=IntegerNat(5),
        Gy=None,
        modulus_bits=448,
        oid="1.3.101.111",  # RFC8410
        canonical="Curve448",
        rawlib=None,
    )

    return curve448

def ed25519_curve():
    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED  # 2**255 - 19
    order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    Gx = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    Gy = 0x6666666666666666666666666666666666666666666666666666666666666658

    ed25519 = _Curve(
        p=IntegerNat(p, public=True),
        order=IntegerNat(order, public=True),
        Gx=IntegerNat(Gx, public=True),
        Gy=IntegerNat(Gy, public=True),
        modulus_bits=255,
        oid="1.3.101.112",  # RFC8410
        canonical="Ed25519",
        rawlib=None,
    )
    return ed25519


def ed448_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 2**448 - 2**224 - 1
    order = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
    Gx = 0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E
    Gy = 0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14


    ed448 = _Curve(
        p=IntegerNat(p, public=True),
        order=IntegerNat(order, public=True),
        Gx=IntegerNat(Gx, public=True),
        Gy=IntegerNat(Gy, public=True),
        modulus_bits=448,
        oid="1.3.101.113",  # RFC8410
        canonical="Ed448",
        rawlib=None,
    )
    return ed448

def _new_curve(p, b, order, Gx, Gy, bits, oid, desc):
    return _Curve(
        p=IntegerNat(p, public=True),
        order=IntegerNat(order, public=True),
        Gx=IntegerNat(Gx, public=True),
        Gy=IntegerNat(Gy, public=True),
        modulus_bits=bits,
        oid=oid,
        canonical=desc,
        rawlib=None,
    )


def p192_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
    b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
    Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
    Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

    return _new_curve(p, b, order, Gx, Gy, 192, "1.2.840.10045.3.1.1", "NIST P-192")


def p224_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
    b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
    Gx = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
    Gy = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34

    return _new_curve(p, b, order, Gx, Gy, 224, "1.3.132.0.33", "NIST P-224")


def p256_curve():
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    return _new_curve(p, b, order, Gx, Gy, 256, "1.2.840.10045.3.1.7", "NIST P-256")


def p384_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

    return _new_curve(p, b, order, Gx, Gy, 384, "1.3.132.0.34", "NIST P-384")


def p521_curve():
    p = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    b = 0x00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
    order = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    Gx = 0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    Gy = 0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

    return _new_curve(p, b, order, Gx, Gy, 521, "1.3.132.0.35", "NIST P-521")

class CurveID:
    P192 = 1
    P224 = 2
    P256 = 3
    P384 = 4
    P521 = 5
    ED25519 = 6
    ED448 = 7
    CURVE25519 = 8
    CURVE448 = 9


class _Curves:
    curves: dict[str, Any] = {}
    p192_names = ["p192", "NIST P-192", "P-192", "prime192v1", "secp192r1", "nistp192"]
    p224_names = ["p224", "NIST P-224", "P-224", "prime224v1", "secp224r1", "nistp224"]
    p256_names = ["p256", "NIST P-256", "P-256", "prime256v1", "secp256r1", "nistp256"]
    p384_names = ["p384", "NIST P-384", "P-384", "prime384v1", "secp384r1", "nistp384"]
    p521_names = ["p521", "NIST P-521", "P-521", "prime521v1", "secp521r1", "nistp521"]
    ed25519_names = ["ed25519", "Ed25519"]
    ed448_names = ["ed448", "Ed448"]
    curve25519_names = ["curve25519", "Curve25519", "X25519"]
    curve448_names = ["curve448", "Curve448", "X448"]

    # For each curve: its names, its ID, and the module and function that create it
    definitions = (
        (p192_names, CurveID.P192, "_nist_ecc", "p192_curve"),
        (p224_names, CurveID.P224, "_nist_ecc", "p224_curve"),
        (p256_names, CurveID.P256, "_nist_ecc", "p256_curve"),
        (p384_names, CurveID.P384, "_nist_ecc", "p384_curve"),
        (p521_names, CurveID.P521, "_nist_ecc", "p521_curve"),
        (ed25519_names, CurveID.ED25519, "_edwards", "ed25519_curve"),
        (ed448_names, CurveID.ED448, "_edwards", "ed448_curve"),
        (curve25519_names, CurveID.CURVE25519, "_montgomery", "curve25519_curve"),
        (curve448_names, CurveID.CURVE448, "_montgomery", "curve448_curve"),
    )

    all_names = [name for definition in definitions for name in definition[0]]

    def load(self, name):
        definition = next((d for d in self.definitions if name in d[0]), None)
        names, curve_id, _, function = definition
        curve_func = globals().get(function)

        curve = curve_func()
        curve.id = curve_id
        self.curves.update(dict.fromkeys(names, curve))
        return curve

    def __getitem__(self, name):
        curve = self.curves.get(name)
        if curve is None:
            curve = self.load(name)
            if not (name in self.curve25519_names or name in self.curve448_names):
                curve.G = EccPoint(curve.Gx, curve.Gy, name)
        return curve

    def items(self):
        for name in self.all_names:
            _ = self[name]
        return self.curves.items()

class Nat:
    def __init__(self, bits: int):
        self.nw = max(1, (bits + 63) // 64)
        self.capacity = self.nw * 64
        self.value = 0

    def set(self, value: int):
        if value < 0 or value.bit_length() > self.capacity:
            raise ValueError("Value does not fit")
        self.value = value

    def get(self) -> int:
        return self.value

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
    def __init__(
        self,
        value: Union[IntegerBase, int],
        _min_bits: int = 0,
        *,
        public: bool = False,
    ) -> None:
        self._public = public or (
            isinstance(value, IntegerBase) and value._public
        )
        self.value = int(value)

        if self.value < 0:
            raise ValueError("Natural numbers cannot be negative")

        self._bits = max(1, self.value.bit_length(), _min_bits)

    def _alloc(self, bits: int) -> None:
        self._bits = max(1, bits)
        self.value = 0

    @classmethod
    def _make(cls, bits: int) -> "IntegerNat":
        obj = cls.__new__(cls)
        obj._alloc(bits)
        obj._public = False
        return obj

    def _adopt(self, other: "IntegerNat") -> "IntegerNat":
        self.value = other.value
        self._bits = other._bits
        self._public = other._public
        return self

    @staticmethod
    def _conv(term: Any) -> "IntegerNat":
        if isinstance(term, IntegerNat):
            return term
        return IntegerNat(operator.index(term))

    def _nw(self) -> int:
        return max(1, (self._bits + 63) // 64)

    def _is_zero(self) -> bool:
        return self.value == 0

    def is_odd(self) -> bool:
        return bool(self.value & 1)

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        return self.value

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return "Integer(%s)" % self.value

    def to_bytes(
        self,
        block_size: Optional[int] = 0,
        byteorder: str = "big",
    ) -> bytes:
        if block_size is None or block_size == 0:
            block_size = max(1, (self.value.bit_length() + 7) // 8)
        return self.value.to_bytes(block_size, byteorder)

    @classmethod
    def from_bytes(
        cls,
        byte_string: Union[bytes, bytearray, memoryview],
        byteorder: str = "big",
        _min_bits: int = 0,
        *,
        public: bool = False,
    ) -> "IntegerNat":
        value = int.from_bytes(byte_string, byteorder)
        return cls(value, _min_bits, public=public)

    # Comparisons

    def _cmp(self, term: Any) -> int:
        other = int(term)
        return (self.value > other) - (self.value < other)

    def __eq__(self, term: Any) -> bool:
        try:
            return self.value == int(term)
        except (TypeError, ValueError):
            return NotImplemented

    def __lt__(self, term: Any) -> bool:
        return self._cmp(term) < 0

    def __le__(self, term: Any) -> bool:
        return self._cmp(term) <= 0

    def __gt__(self, term: Any) -> bool:
        return self._cmp(term) > 0

    def __ge__(self, term: Any) -> bool:
        return self._cmp(term) >= 0

    # Arithmetic

    def __add__(self, term: Any) -> "IntegerNat":
        other = self._conv(term)
        return IntegerNat(
            self.value + other.value,
            max(self._bits, other._bits) + 1,
            public=self._public and other._public,
        )

    __radd__ = __add__

    def __sub__(self, term: Any) -> "IntegerNat":
        other = self._conv(term)
        value = self.value - other.value
        if value < 0:
            raise ValueError("Natural number subtraction underflow")
        return IntegerNat(
            value,
            max(self._bits, other._bits),
            public=self._public and other._public,
        )

    def __mul__(self, factor: Any) -> "IntegerNat":
        other = self._conv(factor)
        return IntegerNat(
            self.value * other.value,
            self._bits + other._bits,
            public=self._public and other._public,
        )

    __rmul__ = __mul__

    def __mod__(self, divisor: Any) -> "IntegerNat":
        divisor = self._check_modulus(divisor)
        return IntegerNat(
            self.value % divisor.value,
            divisor._bits,
            public=self._public and divisor._public,
        )

    @staticmethod
    def _check_modulus(
        modulus: Any,
        name: str = "Modulus",
        zero_error: type[Exception] = ZeroDivisionError,
    ) -> "IntegerNat":
        modulus = IntegerNat._conv(modulus)
        if modulus.value == 0:
            raise zero_error("%s cannot be zero" % name)
        return modulus

    def size_in_bits(self) -> int:
        return max(1, self.value.bit_length())

    def inplace_inverse(self, modulus: Any) -> "IntegerNat":
        modulus = self._check_modulus(modulus)
        self.value = pow(self.value, -1, modulus.value)
        self._bits = modulus._bits
        return self

    def inverse(self, modulus: Any) -> "IntegerNat":
        result = IntegerNat(self, self._bits, public=self._public)
        return result.inplace_inverse(modulus)

def ceil_div(n: int, d: int) -> int:
    r, q = divmod(n, d)
    if (n != 0) and (q != 0): r += 1
    return r

def _copy_point(point):
    copy = point.__class__.__new__(point.__class__)
    copy._curve = point._curve
    copy.curve = point.curve
    copy._point = _py_clone_point(point._point)
    return copy

class VoidPointer:
    def __init__(self): pass
    def get(self): pass


class SmartPointer:
    def __init__(self, raw_pointer: Any) -> None:
        self._raw_pointer = raw_pointer

    def get(self) -> Any: return self._raw_pointer
    def release(self) -> Any: pass

RNG = Callable[[int], bytes]
Int = Union[int, Any]

class EccPoint:
    def __init__(self, x: Union[int, Any], y: Union[int, Any], curve: Optional[str] = "p256") -> None:
        self._curve = _Curves()[curve]
        self.curve = "NIST P-256"

        modulus_bytes = self.size_in_bytes()

        xb = _encode_coordinate(x, modulus_bytes)
        yb = _encode_coordinate(y, modulus_bytes)
        # todo why
        p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
        xb = long_to_bytes(bytes_to_long(xb) % p, modulus_bytes)
        yb = long_to_bytes(bytes_to_long(yb) % p, modulus_bytes)
        self._point = _py_new_point(bytes(xb), bytes(yb), self._curve)

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

    def _get_xy_bytes(self) -> tuple:
        return _py_get_xy_bytes(self._point, self.size_in_bytes(), self._curve)

    def size_in_bytes(self) -> int:
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self) -> int:
        """Size of each coordinate, in bits."""
        return self._curve.modulus_bits


    def __imul__(self, scalar: int) -> "EccPoint":
        self._point = _py_scalar_mul(self._point, int(scalar), self._curve)
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

class DerObjectId:
    def __init__(self): pass

    def decode(self, der_encoded: bytes): return DerObject.decode(self, der_encoded)

    def _decodeFromStream(self, s):
        DerObject._decodeFromStream(self, s)

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

        self.payload = payload
        constructed_bit = 0x20 if constructed else 0x00


        if explicit is not None:
            # 'constructed bit' is always asserted for an EXPLICIT tag
            self._tag_octet = 0x80 | 0x20 | explicit
            self._inner_tag_octet = constructed_bit | asn1Id
        else:
            # Neither IMPLICIT nor EXPLICIT
            self._tag_octet = constructed_bit | asn1Id

    def decode(self, der_encoded: bytes):
        s = BytesIO_EOF(der_encoded)
        self._decodeFromStream(s)
        return self

    def _decodeFromStream(self, s: BytesIO_EOF) -> None:
        self._tag_octet = s.read_byte()
        length = s.read_byte()
        self.payload = s.read(length)
        if hasattr(self, "_inner_tag_octet"):
            p = BytesIO_EOF(self.payload)
            p.read_byte()
            self.payload = p.read(p.read_byte())

class DerBitString(DerObject):
    def __init__(
        self,
        value: Union[bytes, DerObject] = b"",
        implicit: Optional[Union[int, bytes]] = None,
        explicit: Optional[Union[int, bytes]] = None,
    ) -> None:
        DerObject.__init__(self, 0x03, b"", implicit, False, explicit)
        self.value = value

    def _decodeFromStream(self, s):
        DerObject._decodeFromStream(self, s)
        self.value = b""
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
        nr_elements: Optional[Union[int, Any[int]]] = None,
        only_ints_expected: bool = False,
    ) -> DerSequence:
        self._nr_elements = nr_elements
        result = DerObject.decode(self, der_encoded)
        return result

    def _decodeFromStream(self, s: Any) -> None:
        self._seq = []

        # Fill up self.payload
        DerObject._decodeFromStream(self, s)

        # Add one item at a time to self.seq, by scanning self.payload
        p = BytesIO_EOF(self.payload)
        while p.remaining_data() > 0:
            p.set_bookmark()

            der = DerObject()
            der._decodeFromStream(p)
            if der._tag_octet != 0x02:
                self._seq.append(p.data_since_bookmark())
            else:
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
        # Which of these attributes are set depends on the type of key
        self._d: Any = cast(Any, d)
        self._seed: Any = cast(Any, seed)
        self._point: Any = cast(Any, point)
        self._curve = _Curves()[curve]

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

    def _export_SEC1(self):
        modulus_bytes = self.pointQ.size_in_bytes()
        x, y = self.pointQ._xy
        public_key = b"\x04" + x.to_bytes(modulus_bytes) + y.to_bytes(modulus_bytes)
        return public_key

def generate(*, curve) -> EccKey:
    curve_name = curve
    curve_info = _Curves()[curve_name]
    d = random.randrange(1, curve_info.order)
    new_key = EccKey(curve=curve_name, d=d)

    return new_key

def construct(**kwargs) -> EccKey:
    params = cast(dict[str, Any], kwargs)

    curve_name = params["curve"]
    point_x = params.pop("point_x", None)
    point_y = params.pop("point_y", None)

    if None not in (point_x, point_y):
        params["point"] = EccPoint(point_x, point_y, curve_name)
    new_key = EccKey(**params)

    return new_key


def _import_public_der(ec_point, curve_oid=None, curve_name=None):
    for _curve_name, curve in _Curves().items():
        if curve_oid and curve.oid == curve_oid:
            break
        if curve_name == _curve_name:
            break
        
    modulus_bytes = int(curve.p.size_in_bits() / 8)
    x = int.from_bytes(ec_point[1 : modulus_bytes + 1], byteorder="big")
    y = int.from_bytes(ec_point[modulus_bytes + 1 :], byteorder="big")
    return construct(curve=_curve_name, point_x=x, point_y=y)

def _import_rfc5915_der(
    encoded: bytes, curve_oid: Optional[str] = None
) -> EccKey:
    ec_private_key = DerSequence().decode(encoded, nr_elements=(2, 3, 4))
    scalar_bytes = DerObject().decode(ec_private_key[1]).payload
    next_element = 2

    for curve_name, curve in _Curves().items():
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


def _import_pkcs8(encoded):
    import PKCS8
    unwrapped = PKCS8.unwrap(encoded)
    private_key, params = unwrapped
    curve_oid = DerObjectId().decode(params).value
    key = _import_rfc5915_der(private_key, curve_oid)
    return key

def import_key(encoded, curve_name=None):
    if encoded.startswith(b"-----"):
        text_encoded = encoded.decode("latin-1")
        ecparams_start = "-----BEGIN EC PARAMETERS-----"
        ecparams_end = "-----END EC PARAMETERS-----"
        text_encoded = re.sub(ecparams_start + ".*?" + ecparams_end, "", text_encoded, flags=re.DOTALL)
        
        der_encoded, _, _ = decode(text_encoded)
        result = _import_pkcs8(der_encoded)
        return result

    # SEC1
    if len(encoded) > 0 and encoded[0] in (0x02, 0x03, 0x04):
        return _import_public_der(encoded, curve_name=curve_name)

