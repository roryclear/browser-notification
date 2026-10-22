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

from Crypto.Math.Numbers import Integer
from Crypto.Util.asn1 import DerBitString, DerObjectId, DerOctetString, DerSequence
from Crypto.PublicKey._point import EccPoint, EccXPoint, _curves

RNG = Callable[[int], bytes]
Int = Union[int, Any]


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
        point: Optional[Union[EccPoint, EccXPoint]] = None,
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
        blind = Integer.random_range(min_inclusive=1, max_exclusive=order)

        blind_d = self._d * blind
        inv_blind_k = (blind * k).inverse(order)

        r = (self._curve.G * k)._x % order
        s = inv_blind_k * (blind * z + blind_d * r) % order
        return (r, s)

    @property
    def pointQ(self) -> EccPoint:
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
    x = Integer.from_bytes(ec_point[1 : modulus_bytes + 1])
    y = Integer.from_bytes(ec_point[modulus_bytes + 1 :])
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

    d = Integer.from_bytes(scalar_bytes)
    return construct(curve=curve_name, d=d, point_x=point_x, point_y=point_y)


def _import_pkcs8(encoded, passphrase, max_iteration_count=None, threads=1, max_memory=None):
    from Crypto.IO import PKCS8
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
    from Crypto.IO import PEM

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
