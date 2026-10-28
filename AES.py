from typing import Any, Union, Optional, cast
import os
import struct
import base64, json
import copy, time
import secrets
from urllib.parse import urlparse
import hashlib, re
from abc import ABC
from binascii import a2b_base64
import operator, random


KEY_LENGTH = 16
NONCE_LENGTH = 12

_GF_R = 0xE1000000000000000000000000000000

SHA256_digest_size = 32
SHA256_block_size = 64

def generate(*, curve):
    curve_name = curve
    curve_info = _Curves()[curve_name]
    d = random.randrange(1, curve_info.order)
    new_key = EccKey(curve=curve_name, d=d)

    return new_key

class _Curve:
    def __init__(self, p=None, order=None, Gx=None, Gy=None, modulus_bits=None, oid=None, canonical=None):
        self.p = p
        self.order = order
        self.Gx = Gx
        self.Gy = Gy
        self.modulus_bits = modulus_bits
        self.oid = oid
        self.canonical = canonical

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
        canonical="Curve25519"
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
    )

    return curve448

def ed25519_curve():
    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED  # 2**255 - 19
    order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    Gx = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    Gy = 0x6666666666666666666666666666666666666666666666666666666666666658

    ed25519 = _Curve(
        p=IntegerNat(p),
        order=IntegerNat(order),
        Gx=IntegerNat(Gx),
        Gy=IntegerNat(Gy),
        modulus_bits=255,
        oid="1.3.101.112",  # RFC8410
        canonical="Ed25519",
    )
    return ed25519


def ed448_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 2**448 - 2**224 - 1
    order = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
    Gx = 0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E
    Gy = 0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14


    ed448 = _Curve(
        p=IntegerNat(p),
        order=IntegerNat(order),
        Gx=IntegerNat(Gx),
        Gy=IntegerNat(Gy),
        modulus_bits=448,
        oid="1.3.101.113",  # RFC8410
        canonical="Ed448",
    )
    return ed448

def _new_curve(p, order, Gx, Gy, bits, oid, desc):
    return _Curve(
        p=IntegerNat(p),
        order=IntegerNat(order),
        Gx=IntegerNat(Gx),
        Gy=IntegerNat(Gy),
        modulus_bits=bits,
        oid=oid,
        canonical=desc,
    )


def p192_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
    Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
    Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

    return _new_curve(p, order, Gx, Gy, 192, "1.2.840.10045.3.1.1", "NIST P-192")


def p224_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
    Gx = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
    Gy = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34

    return _new_curve(p, order, Gx, Gy, 224, "1.3.132.0.33", "NIST P-224")


def p256_curve():
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    return _new_curve(p, order, Gx, Gy, 256, "1.2.840.10045.3.1.7", "NIST P-256")


def p384_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

    return _new_curve(p, order, Gx, Gy, 384, "1.3.132.0.34", "NIST P-384")


def p521_curve():
    p = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    order = 0x000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    Gx = 0x000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    Gy = 0x0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

    return _new_curve(p, order, Gx, Gy, 521, "1.3.132.0.35", "NIST P-521")

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

def random_integerNat(max_bits):
    bits = max_bits
    bytes_needed = ((bits - 1) // 8) + 1
    significant_bits_msb = 8 - (bytes_needed * 8 - bits)
    msb = secrets.token_bytes(1)[0]
    msb &= (1 << significant_bits_msb) - 1
    ret = IntegerNat.from_bytes(bytes([msb]) + secrets.token_bytes(bytes_needed - 1))
    return ret


def random_range(min_inclusive=None, max_inclusive=None, max_exclusive=None,):
    max_inclusive = max_exclusive - 1
    norm_maximum = IntegerNat(max_inclusive) - min_inclusive
    bits_needed = norm_maximum.size_in_bits()

    while True:
        norm_candidate = random_integerNat(max_bits=bits_needed)
        if norm_candidate <= norm_maximum:
            return norm_candidate + min_inclusive

class IntegerNat:
    def __init__(self, value, _min_bits: int = 0) -> None:
        self._public = False
        self.value = int(value)
        self._bits = max(1, self.value.bit_length(), _min_bits)

    def _alloc(self, bits: int) -> None:
        self._bits = max(1, bits)
        self.value = 0

    @classmethod
    def _make(cls, bits: int):
        obj = cls.__new__(cls)
        obj._alloc(bits)
        obj._public = False
        return obj

    def _adopt(self, other: "IntegerNat"):
        self.value = other.value
        self._bits = other._bits
        self._public = other._public
        return self

    @staticmethod
    def _conv(term: Any): return IntegerNat(operator.index(term))
    def __index__(self): return self.value
    
    def to_bytes(
        self,
        block_size: Optional[int] = 0,
        byteorder: str = "big",
    ) -> bytes:
        if block_size is None or block_size == 0:
            block_size = max(1, (self.value.bit_length() + 7) // 8)
        return self.value.to_bytes(block_size, byteorder)

    @classmethod
    def from_bytes(cls, byte_string: Union[bytes, bytearray, memoryview]):
        return IntegerNat(int.from_bytes(byte_string, "big"))

    def _cmp(self, term: Any) -> int:
        other = int(term)
        return (self.value > other) - (self.value < other)

    def __le__(self, term: Any) -> bool: return self._cmp(term) <= 0

    def __gt__(self, term: Any) -> bool: return self._cmp(term) > 0
    def __add__(self, term: Any):
        other = self._conv(term)
        return IntegerNat(self.value + other.value, max(self._bits, other._bits) + 1)

    __radd__ = __add__

    def __sub__(self, term: Any):
        other = self._conv(term)
        value = self.value - other.value
        return IntegerNat(value, max(self._bits, other._bits))

    def __mul__(self, factor: Any):
        other = self._conv(factor)
        return IntegerNat(self.value * other.value, self._bits + other._bits)

    __rmul__ = __mul__

    def __mod__(self, divisor: Any):
        divisor = self._check_modulus(divisor)
        return IntegerNat(self.value % divisor.value, divisor._bits)

    @staticmethod
    def _check_modulus(
        modulus: Any,
        name: str = "Modulus",
        zero_error: type[Exception] = ZeroDivisionError,
    ):
        modulus = IntegerNat._conv(modulus)
        if modulus.value == 0:
            raise zero_error("%s cannot be zero" % name)
        return modulus

    def size_in_bits(self) -> int:
        return max(1, self.value.bit_length())

    def inplace_inverse(self, modulus: Any):
        modulus = self._check_modulus(modulus)
        self.value = pow(self.value, -1, modulus.value)
        self._bits = modulus._bits
        return self

    def inverse(self, modulus: Any):
        result = IntegerNat(self, self._bits)
        return result.inplace_inverse(modulus)

def decode(pem_data: str) -> tuple[bytes, str, bool]:
    r = re.compile(r"\s*-----BEGIN (.*)-----\s+")
    m = r.match(pem_data)
    marker = m.group(1)
    lines = pem_data.replace(" ", "").split()
    data = a2b_base64("".join(lines[1:-1]))
    enc_flag = False

    return (data, marker, enc_flag)

def bytes_to_long(s: Union[bytes, bytearray, memoryview]) -> int:
    return int.from_bytes(s, "big")

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
        blind = random_range(min_inclusive=1, max_exclusive=order)

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

    def public_key(self):
        return EccKey(curve=self._curve.canonical, point=self.pointQ)

    def _export_SEC1(self):
        modulus_bytes = self.pointQ.size_in_bytes()
        x, y = self.pointQ._xy
        public_key = b"\x04" + x.to_bytes(modulus_bytes) + y.to_bytes(modulus_bytes)
        return public_key

def _encode_coordinate(value, length) -> bytes:
    encoded = long_to_bytes(int(value), length)
    return encoded

def _py_new_point(xb: bytes, yb: bytes, curve: "_Curve") -> dict:
    p = int(curve.p)
    x = int.from_bytes(xb, "big") % p
    y = int.from_bytes(yb, "big") % p
    if x == 0 and y == 0: return {"x": 0, "y": 1, "z": 0}
    return {"x": x, "y": y, "z": 1}

def _py_get_xy_bytes(point: dict, modulus_bytes: int, curve: "_Curve") -> tuple:
    p = int(curve.p)
    X, Y, Z = point["x"], point["y"], point["z"]
    if Z % p == 0: return bytearray(modulus_bytes), bytearray(modulus_bytes)
    Zinv = pow(Z, -1, p)
    x = (X * Zinv) % p
    y = (Y * Zinv) % p
    return (bytearray(x.to_bytes(modulus_bytes, "big")),
            bytearray(y.to_bytes(modulus_bytes, "big")))

def _py_clone_point(point: dict) -> dict: return {"x": point["x"], "y": point["y"], "z": point["z"]}

def _copy_point(point):
    copy = point.__class__.__new__(point.__class__)
    copy._curve = point._curve
    copy.curve = point.curve
    copy._point = _py_clone_point(point._point)
    return copy

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

def _py_scalar_mul(point: dict, k: int, curve) -> dict:
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

    def copy(self):return _copy_point(self)

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
        return IntegerNat(int.from_bytes(xb)), IntegerNat(int.from_bytes(yb))

    def _get_xy_bytes(self) -> tuple:
        return _py_get_xy_bytes(self._point, self.size_in_bytes(), self._curve)

    def size_in_bytes(self) -> int:
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self) -> int:
        """Size of each coordinate, in bits."""
        return self._curve.modulus_bits


    def __imul__(self, scalar: int):
        self._point = _py_scalar_mul(self._point, int(scalar), self._curve)
        return self

    def __mul__(self, scalar: int):
        """Return a new point, the scalar product of this one"""

        np = self.copy()
        np *= scalar
        return np

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

    def decode(self, der_encoded: bytes, nr_elements):
        self._nr_elements = nr_elements
        result = DerObject.decode(self, der_encoded)
        return result

    def _decodeFromStream(self, s: BytesIO_EOF) -> None:
        self._seq = []

        s.read_byte()
        length = s.read_byte()
        if length > 127:
            encoded_length = s.read(length & 0x7F)
            length = bytes_to_long(encoded_length)

        self.payload = s.read(length)

        p = BytesIO_EOF(self.payload)
        while p.remaining_data() > 0:
            p.set_bookmark()
            p.read_byte()
            length = p.read_byte()
            if length > 127:
                encoded_length = p.read(length & 0x7F)
                length = bytes_to_long(encoded_length)

            self.payload = p.read(length)
            self._seq.append(p.data_since_bookmark())

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
                
def unwrap(p8_private_key: bytes):
    pk_info, algo = DerSequence(), DerSequence()
    pk_info._decodeFromStream(BytesIO_EOF(p8_private_key))
    algo._decodeFromStream(BytesIO_EOF(pk_info._seq[1]))
    private_key = DerObject().decode(pk_info._seq[2]).payload
    return (private_key, algo._seq[1])

def _import_pkcs8(encoded):
    unwrapped = unwrap(encoded)
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

class SHA256Hash:
    def __init__(self, data=None):
        self._hash = hashlib.sha256()
        if data: self.update(data)

    def update(self, data): self._hash.update(data)

    def copy(self):
        clone = SHA256Hash()
        clone._hash = self._hash.copy()
        return clone
        
def strxor(term1, term2, length=None): return bytes(a ^ b for a, b in zip(term1[:length], term2[:length]))

class HMAC:
    def __init__(self, key, msg = b"") -> None:
        self.digest_size = SHA256_digest_size
        if len(key) <= SHA256_digest_size:
            key_0 = key + b"\x00" * (SHA256_block_size - len(key))
        else:
            hash_k = SHA256Hash(key)._hash.digest()()
            key_0 = hash_k + b"\x00" * (SHA256_block_size - len(hash_k))

        key_0_ipad = strxor(key_0, b"\x36" * len(key_0))
        self._inner = SHA256Hash(key_0_ipad)
        self._inner.update(msg)
        key_0_opad = strxor(key_0, b"\x5c" * len(key_0))
        self._outer = SHA256Hash(key_0_opad)

    def digest(self) -> bytes:
        frozen_outer_hash = self._outer.copy()
        frozen_outer_hash.update(self._inner._hash.digest())
        return frozen_outer_hash._hash.digest()

def _HKDF_expand(prk, info, L: int) -> bytes:
    t = [b""]
    n = 1
    tlen = 0
    while tlen < L:
        hmac = HMAC(prk, t[-1] + info + struct.pack("B", n))
        t.append(hmac.digest())
        tlen += SHA256_digest_size
        n += 1
    okm = b"".join(t)
    return okm[:L]


def HKDF(master, key_len, salt, context):
    prk = HMAC(salt, master).digest()
    okm = _HKDF_expand(prk, context, key_len)
    return okm[:key_len]

class DssSigScheme:
    def __init__(self, key: Union[Any, Any], order: Any) -> None:
        self._key = key
        self._order = order

        self._order_bits = self._order.size_in_bits()
        self._order_bytes = (self._order_bits - 1) // 8 + 1

    def sign(self, msg_hash) -> bytes:
        nonce = self._compute_nonce()
        z = int.from_bytes(msg_hash.digest()[:self._order_bytes], byteorder="big")
        sig_pair = self._key._sign(z, nonce)
        output = b"".join([long_to_bytes(x, self._order_bytes) for x in sig_pair])
        return output

class FipsEcDsaSigScheme(DssSigScheme):
    def __init__(self, key: Any) -> None:
        order = key._curve.order
        super().__init__(key, order)
        self._randfunc = None

    def _compute_nonce(self):
        n = int(self._key._curve.order)
        return secrets.randbelow(n - 1) + 1

def _gf_mult(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GF_R
        else:
            v >>= 1
    return z


class _GHASH:
    __slots__ = ("_h", "_last_y")

    def __init__(self, subkey: bytes) -> None:
        self._h = bytes_to_long(subkey)   # H
        self._last_y = 0                  # Y_0 = 0

    def update(self, block_data) -> "_GHASH":
        data = bytes(block_data)
        h = self._h
        y = self._last_y
        for i in range(0, len(data), 16):
            y = _gf_mult(y ^ bytes_to_long(data[i:i + 16]), h)
        self._last_y = y
        return self

    @property
    def digest(self) -> bytes: return long_to_bytes(self._last_y, 16)

def b64urlencode(data): return base64.urlsafe_b64encode(data).replace(b"=", b"").decode("utf8")

def sign(claims, key):
    header = b64urlencode(b'{"typ":"JWT","alg":"ES256"}')
    claims = b64urlencode(
        json.dumps(
            claims, separators=(",", ":"), sort_keys=True
        ).encode("utf8")
    )

    token = "{}.{}".format(header, claims)

    signer = FipsEcDsaSigScheme(key)

    # todo patch throw in lib
    import hashlib
    signature = signer.sign(hashlib.sha256(token.encode("utf8")))

    return "{}.{}".format(token, b64urlencode(signature))

class Vapid:
    def __init__(self, private_key):
        self._schema = "vapid"
        self.conf = {}
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def from_pem(cls, private_key):
        return cls(import_key(private_key))

    @classmethod
    def from_der(cls, private_key):
        der = b64urldecode(private_key)
        return cls(import_key(der))

    @classmethod
    def from_file(cls, private_key_file=None):
        with open(private_key_file, "rb") as f:
            return cls.from_pem(f.read())

    def _base_sign(self, claims):
        cclaims = copy.deepcopy(claims)
        cclaims["exp"] = int(time.time()) + 86400
        return cclaims

    def sign(self, claims):
        token = sign(self._base_sign(claims), self._private_key)

        public_key = self._public_key._export_SEC1()

        return {
            "Authorization": "{} t={},k={}".format(
                self._schema, token, b64urlencode(public_key)
            )
        }

def derive_key(salt, private_key, dh, auth_secret):
    receiver_pub = import_key(dh, curve_name="P-256")
    shared_point = receiver_pub.pointQ * private_key._d
    secret = int(shared_point.x).to_bytes(32, "big")
    sender_pub = private_key.public_key()._export_SEC1()
    context = b"WebPush: info\x00" + dh + sender_pub
    secret = HKDF(secret, 32, auth_secret, context=context)
    key = HKDF(secret, KEY_LENGTH, salt, context=b"Content-Encoding: aes128gcm\x00")
    nonce = HKDF(secret, NONCE_LENGTH, salt, context=b"Content-Encoding: nonce\x00")
    return key, nonce

def iv(base, counter):
    (mask,) = struct.unpack("!Q", base[4:])
    return base[:4] + struct.pack("!Q", counter ^ mask)

def b64urldecode(data):
    padded = data.replace(b"+", b"-").replace(b"/", b"_") + b"===="[len(data) % 4 :]
    return base64.urlsafe_b64decode(padded)

def aes_encrypt(content, headers=None):

    with open("notif_keys.json") as f: subscription_info = json.load(f)

    receiver_key = b64urldecode(subscription_info["keys"]["p256dh"].encode("ascii"))

    auth_key = b64urldecode(subscription_info["keys"]["auth"].encode("ascii"))

    endpoint = subscription_info["endpoint"]
    url = urlparse(endpoint)

    vapid_claims = {"sub": "mailto:fake@fake.invalid", "aud": f"{url.scheme}://{url.netloc}"}

    vv = Vapid.from_file("vapid_private.pem")
    headers = vv.sign(vapid_claims)

    rs = 4096
    private_key = generate(curve="P-256")
    def encrypt_record(key, nonce, counter, buf):
        nonce = iv(nonce, counter)
        cipher = GcmMode(key, nonce)
        ciphertext = encrypt(cipher=cipher, plaintext=buf + b"\x02")
        tag = _compute_mac(cipher)
        return ciphertext + tag

    def compose_aes128gcm(salt, content, rs, keyid):
        header = salt
        header += struct.pack("!L", rs)
        header += struct.pack("!B", len(keyid))
        header += keyid
        return header + content

    salt = os.urandom(16)

    key, nonce = derive_key(
        salt=salt,
        private_key=private_key,
        dh=receiver_key,
        auth_secret=auth_key,
    )

    overhead = 1 + 16
    chunk_size = rs - overhead

    result = b""
    counter = 0

    for i in range(0, len(content), chunk_size):
        result += encrypt_record(
            key, nonce, counter, content[i:i + chunk_size]
        )
        counter += 1

    public_key = private_key.public_key()._export_SEC1()

    headers.update({"Content-Encoding": "aes128gcm", "TTL": "60",})

    return compose_aes128gcm(salt, result, rs, keyid=public_key), headers, endpoint


class GcmMode:
    def __init__(self, key: Any, nonce: Any) -> None:
        self.block_size = 16
        self.nonce = bytes(nonce)
        self._key = bytes(key)
        self._tag: Optional[bytes] = None

        self._mac_len = 16
        self._no_more_assoc_data = False
        self._auth_len = 0
        self._msg_len = 0
        hash_subkey = EcbMode(key).encrypt(b"\x00" * 16)

        j0 = self.nonce + b"\x00\x00\x00\x01"

        nonce_ctr = j0[:12]
        iv_ctr = (bytes_to_long(j0) + 1) & 0xFFFFFFFF
        self._cipher = _create_ctr_cipher(
            key,
            initial_value=iv_ctr.to_bytes(4, byteorder="big", signed=False),
            nonce=nonce_ctr,
        )
        self._tag_cipher = _create_ctr_cipher(key, initial_value=j0, nonce=b"")
        self._signer = _GHASH(hash_subkey)
        self._cache = b""

    def _update(self, data):
        if len(self._cache) > 0:
            filler = min(16 - len(self._cache), len(data))
            self._cache += bytes(data[:filler])
            data = data[filler:]

            if len(self._cache) < 16: return

            self._signer.update(self._cache)
            self._cache = b""

        update_len = len(data) // 16 * 16
        self._cache = bytes(data[update_len:])
        if update_len > 0:
            if update_len < len(data):
                data = memoryview(data)[:update_len]
            self._signer.update(data)

def _compute_mac(cipher: "GcmMode") -> bytes:
    cipher._update(b"\x00" * (16 - len(cipher._cache)))
    cipher._update(long_to_bytes(8 * cipher._auth_len, 8))
    cipher._update(long_to_bytes(8 * cipher._msg_len, 8))
    s_tag = cipher._signer.digest                     # was: get_raw_buffer(...)
    cipher._tag = cipher._tag_cipher.encrypt(s_tag)[: cipher._mac_len]
    return cipher._tag

def encrypt(cipher, plaintext):
    ciphertext = cipher._cipher.encrypt(plaintext)
    cipher._update(ciphertext)
    cipher._msg_len += len(plaintext)
    return ciphertext

def _create_ctr_cipher(key, initial_value, nonce):
    cipher_state = BlockState(key)
    counter_len = 16 - len(nonce)
    initial_counter_block = nonce + initial_value
    return CtrMode(cipher_state, initial_counter_block,
                    len(nonce), counter_len, False)

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

def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    n = operator.index(n)
    length = max((n.bit_length() + 7) // 8, 1)
    if blocksize > 0: length = ceil_div(length, blocksize) * blocksize
    return n.to_bytes(length, "big")

def ceil_div(n: int, d: int) -> int:
    r, q = divmod(n, d)
    if (n != 0) and (q != 0): r += 1
    return r

class EcbMode:
    def __init__(self, key: bytes) -> None:
        self.block_size = 16
        self._state = BlockState(key)

    def encrypt(self, plaintext, output=None):
        data = bytes(plaintext)
        result = self._state.encrypt(data)

        if output is not None:
            output[:] = result
            return None
        return result

class CtrMode:
    def __init__(
        self,
        block_cipher,
        initial_counter_block,
        prefix_len: int,
        counter_len: int,
        little_endian: bool,
    ):

        self._cipher      = block_cipher
        self.block_size   = len(initial_counter_block)
        self._counter     = bytearray(initial_counter_block)
        self._prefix_len  = prefix_len
        self._counter_len = counter_len
        self._little_endian = little_endian

        self._keystream   = None
        self._used        = 0

        self._bytes_processed = 0
        self._max_bytes = (1 << (8 * counter_len)) * self.block_size

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

    def _consume(self, n: int) -> bytes:
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

    def encrypt(self, plaintext):
        data = bytes(plaintext)
        ks = self._consume(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))