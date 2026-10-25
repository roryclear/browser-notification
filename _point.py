# This file is licensed under the BSD 2-Clause License.
# See https://opensource.org/licenses/BSD-2-Clause for details.

from __future__ import annotations

import importlib
from typing import Any, Optional, TypeVar, Union

from Crypto.Math._IntegerBase import IntegerBase
from Crypto.Math.Numbers import Integer
from Crypto.Random.random import getrandbits
from Crypto.Util._raw_api import (
    SmartPointer,
    VoidPointer,
    c_size_t,
    c_uint8_ptr,
    c_uint8_ptr_len,
    c_uint8_ptr_out,
    c_ulonglong,
    null_pointer,
)
from Crypto.Util.number import bytes_to_long, long_to_bytes

from _curve import _Curve

# EccPoint or EccXPoint (defined below)
_PointT = TypeVar("_PointT", "EccPoint", "EccXPoint")

def _curve_context(curve: _Curve) -> Any:
    return null_pointer if curve.context is None else curve.context.get()


def _clone_raw_point(curve: _Curve, point: Union[EccPoint, EccXPoint]):
    raw_point = VoidPointer()
    curve.rawlib.clone(raw_point.address_of(), point._point.get())
    return SmartPointer(raw_point.get(), curve.rawlib.free_point)


def _copy_point(point: _PointT) -> _PointT:
    """A copy of an EccPoint or EccXPoint, of the same class"""

    copy = point.__class__.__new__(point.__class__)
    copy._curve = point._curve
    copy.curve = point.curve
    copy._point = _clone_raw_point(point._curve, point)
    return copy


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


_nist_curve_ids = (CurveID.P192, CurveID.P224, CurveID.P256, CurveID.P384, CurveID.P521)


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
        names, curve_id, module_name, function = definition
        module = importlib.import_module(module_name)
        curve = getattr(module, function)()
        curve.id = curve_id
        self.curves.update(dict.fromkeys(names, curve))
        return curve

    def __getitem__(self, name):
        curve = self.curves.get(name)
        if curve is None:
            curve = self.load(name)
            if name in self.curve25519_names or name in self.curve448_names:
                curve.G = EccXPoint(curve.Gx, name)
            else:
                curve.G = EccPoint(curve.Gx, curve.Gy, name)
        return curve

    def items(self):
        for name in self.all_names:
            _ = self[name]
        return self.curves.items()


_curves = _Curves()


class EccPoint:
    """A class to model a point on an Elliptic Curve.

    The class supports operators for:

    * Adding two points: ``R = S + T``
    * In-place addition: ``S += T``
    * Negating a point: ``R = -T``
    * Comparing two points: ``if S == T: ...`` or ``if S != T: ...``
    * Multiplying a point by a scalar: ``R = S*k``
    * In-place multiplication by a scalar: ``T *= k``

    :ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
    :vartype curve: string

    :ivar x: The affine X-coordinate of the ECC point
    :vartype x: integer

    :ivar y: The affine Y-coordinate of the ECC point
    :vartype y: integer

    :ivar xy: The tuple with affine X- and Y- coordinates
    """

    def __init__(self, x: Union[int, Integer], y: Union[int, Integer], curve: Optional[str] = "p256") -> None:
        self._curve = _curves[curve]
        self.curve = self._curve.canonical

        modulus_bytes = self.size_in_bytes()

        xb = long_to_bytes(x, modulus_bytes)
        yb = long_to_bytes(y, modulus_bytes)
        if self._curve.id in _nist_curve_ids:
            p = int(self._curve.p)
            xb = long_to_bytes(bytes_to_long(xb) % p, modulus_bytes)
            yb = long_to_bytes(bytes_to_long(yb) % p, modulus_bytes)

        new_point = self._curve.rawlib.new_point
        free_func = self._curve.rawlib.free_point

        raw_point = VoidPointer()
        context = _curve_context(self._curve)
        new_point(raw_point.address_of(), c_uint8_ptr(xb), c_uint8_ptr(yb), c_size_t(modulus_bytes), context)
        self._point = SmartPointer(raw_point.get(), free_func)


    def copy(self) -> EccPoint: return _copy_point(self)

    @property
    def _x(self) -> Integer:
        return self._xy[0]

    @property
    def _xy(self) -> tuple[Integer, Integer]:
        xb, yb = self._get_xy_bytes()
        return (Integer.from_bytes(xb), Integer.from_bytes(yb))

    def _get_xy_bytes(self) -> tuple[bytearray, bytearray]:
        modulus_bytes = self.size_in_bytes()
        xb = bytearray(modulus_bytes)
        yb = bytearray(modulus_bytes)
        get_xy = self._curve.rawlib.get_xy
        with c_uint8_ptr_out(xb) as xb_ptr, c_uint8_ptr_out(yb) as yb_ptr:
            result = get_xy(xb_ptr, yb_ptr, c_size_t(modulus_bytes), self._point.get())
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
        sb = long_to_bytes(scalar, self.size_in_bytes())
        sb_ptr, sb_len = c_uint8_ptr_len(sb)
        self._curve.rawlib.scalar(self._point.get(), sb_ptr, c_size_t(sb_len), c_ulonglong(getrandbits(64)))
        return self

    def __mul__(self, scalar: int) -> EccPoint:
        """Return a new point, the scalar product of this one"""

        np = self.copy()
        np *= scalar
        return np

class EccXPoint:
    def __init__(self, x: Optional[Union[int, Integer]], curve: Optional[str]) -> None:
        self._curve = _curves[curve]
        self.curve = self._curve.canonical

        new_point = self._curve.rawlib.new_point
        free_func = self._curve.rawlib.free_point

        context = _curve_context(self._curve)

        modulus_bytes = self.size_in_bytes()

        if x is None:
            xb = null_pointer
        else:
            xb = c_uint8_ptr(long_to_bytes(x, modulus_bytes))

        raw_point = VoidPointer()
        new_point(raw_point.address_of(), xb, c_size_t(modulus_bytes), context)

        # Ensure that object disposal of this Python object will (eventually)
        # free the memory allocated by the raw library for the EC point
        self._point = SmartPointer(raw_point.get(), free_func)



    def size_in_bytes(self) -> int:
        """Size of each coordinate, in bytes."""
        return (self.size_in_bits() + 7) // 8

    def size_in_bits(self) -> int:
        """Size of each coordinate, in bits."""
        return self._curve.modulus_bits
