from __future__ import annotations

import binascii
import re
import struct
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Literal,
    Optional,
    TypedDict,
    Union,
    cast,
    overload,
)

from Crypto import IncorrectPassphraseError, KdfLimitError, PassphraseRequiredError
from Crypto.Hash import SHA512, SHAKE256
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import (
    _create_subject_public_key_info,
    _expand_subject_public_key_info,
    _extract_subject_public_key_info,
)
from Crypto.Random import get_random_bytes
from Crypto.Util._bytes import tobytes
from Crypto.Util.asn1 import DerBitString, DerObjectId, DerOctetString, DerSequence

from Crypto.PublicKey._point import CurveID as _CurveID
from Crypto.PublicKey._point import EccPoint, EccXPoint, _curves

if TYPE_CHECKING:
    from typing_extensions import Unpack

    from Crypto.IO._PBES import ProtParams

RNG = Callable[[int], bytes]
Int = Union[int, Integer]


class _CurveRequired(TypedDict):
    curve: str


class ConstructParams(_CurveRequired, total=False):
    d: Union[int, Integer]
    seed: bytes
    point_x: Optional[Union[int, Integer]]
    point_y: Optional[Union[int, Integer]]


# The curves whose private key is a seed, and its length
_SEED_LENGTHS = {
    _CurveID.ED25519: 32,
    _CurveID.ED448: 57,
    _CurveID.CURVE25519: 32,
    _CurveID.CURVE448: 56,
}


class EccKey:
    def __init__(
        self,
        *,
        curve: Optional[str] = None,
        d: Optional[Union[int, Integer]] = None,
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

    def has_private(self) -> bool:
        """``True`` if this key can be used for making signatures or decrypting data."""

        return self._d is not None

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
    def d(self) -> int:
        if not self.has_private():
            raise ValueError("This is not a private ECC key")
        return int(self._d)

    @property
    def pointQ(self) -> EccPoint:
        if self._point is None:
            self._point = self._curve.G * self._d
        return self._point

    def public_key(self) -> EccKey:
        """A matching ECC public key.

        Returns:
            a new :class:`EccKey` object
        """

        return EccKey(curve=self._curve.canonical, point=self.pointQ)

    def _export_SEC1(self, compress):
        if not self._curve.is_weierstrass:
            raise ValueError("SEC1 format is only supported for NIST P curves")

        # See 2.2 in RFC5480 and 2.3.3 in SEC1
        #
        # The first byte is:
        # - 0x02:   compressed, only X-coordinate, Y-coordinate is even
        # - 0x03:   compressed, only X-coordinate, Y-coordinate is odd
        # - 0x04:   uncompressed, X-coordinate is followed by Y-coordinate
        #
        # PAI is in theory encoded as 0x00.

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
        if ext_format not in ("PEM", "DER", "OpenSSH", "SEC1", "raw"):
            raise ValueError("Unknown format '%s'" % ext_format)

        if self.has_private():
            from Crypto.IO import PKCS8

            PKCS8._check_kdf_params(threads=threads)
            if passphrase is not None:
                passphrase = tobytes(passphrase)
                if not passphrase:
                    raise ValueError("Empty passphrase")
            elif protection or prot_params:
                raise ValueError("'protection' and 'prot_params' require a passphrase")

            if use_pkcs8 is False:
                if self._curve.is_edwards:
                    raise ValueError("'pkcs8' must be True for EdDSA curves")
                if self._curve.is_montgomery:
                    raise ValueError("'pkcs8' must be True for Curve25519")
                if protection is not None:
                    raise ValueError("'protection' is only supported for PKCS#8")

            # The parameters for the encryption with PKCS#8
            enc_args = {"protection": protection, "prot_params": prot_params, "randfunc": randfunc}

            if ext_format == "PEM":
                if use_pkcs8:
                    if passphrase:
                        return self._export_private_encrypted_pkcs8_in_clear_pem(
                            passphrase, threads=threads, **enc_args
                        )
                    else:
                        return self._export_private_clear_pkcs8_in_clear_pem()
                else:
                    if prot_params is not None:
                        raise ValueError("'prot_params' is only supported for PKCS#8")
                    return self._export_private_pem(passphrase, randfunc=randfunc)
            elif ext_format == "DER":
                # DER
                if passphrase and not use_pkcs8:
                    raise ValueError("Private keys can only be encrypted with DER using PKCS#8")
                if use_pkcs8:
                    return self._export_pkcs8(passphrase=passphrase, threads=threads, **enc_args)
                else:
                    return self._export_rfc5915_private_der()
            else:
                raise ValueError("Private keys cannot be exported in the '%s' format" % ext_format)
        else:  # Public key
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


def generate(*, curve: str, randfunc: Optional[RNG] = None) -> EccKey:
    curve_name = curve
    curve_info = _curves[curve_name]
    randfunc = get_random_bytes
    d = Integer.random_range(min_inclusive=1, max_exclusive=curve_info.order, randfunc=randfunc)
    new_key = EccKey(curve=curve_name, d=d)

    return new_key


def construct(**kwargs: Unpack[ConstructParams]) -> EccKey:
    params = cast(dict[str, Any], kwargs)

    curve_name = params["curve"]
    curve = _curves[curve_name]
    point_x = params.pop("point_x", None)
    point_y = params.pop("point_y", None)

    if None not in (point_x, point_y):
        params["point"] = EccPoint(point_x, point_y, curve_name)
    new_key = EccKey(**params)

    # Validate that the private key matches the public one
    # because EccKey will not do that automatically
    if new_key.has_private() and "point" in params:
        pub_key = curve.G * new_key._d
        if pub_key.xy != (int(point_x), int(point_y)):
            raise ValueError("Private and public ECC keys do not match")

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
    encoded: bytes, passphrase: Optional[bytes], curve_oid: Optional[str] = None
) -> EccKey:
    ec_private_key = DerSequence().decode(encoded, nr_elements=(2, 3, 4))
    scalar_bytes = DerOctetString().decode(ec_private_key[1]).payload
    next_element = 2

    for curve_name, curve in _curves.items():  # noqa: B007 (used after the loop)
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
    # The optional publicKey of a OneAsymmetricKey (RFC 5958),
    # which must match the private key
    public_key = unwrapped.public_key

    curve_oid = DerObjectId().decode(params).value
    key = _import_rfc5915_der(private_key, passphrase, curve_oid)
    if public_key is not None:
        # ECPoint (RFC 5480), as in the subjectPublicKeyInfo
        point = _import_public_der(public_key, curve_oid=curve_oid).pointQ

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
    from Crypto.IO import PEM, PKCS8

    PKCS8._check_kdf_params(max_iteration_count, threads, max_memory)
    encoded = tobytes(encoded)

    if encoded.startswith(b"-----"):
        text_encoded = encoded.decode("latin-1")
        ecparams_start = "-----BEGIN EC PARAMETERS-----"
        ecparams_end = "-----END EC PARAMETERS-----"
        text_encoded = re.sub(ecparams_start + ".*?" + ecparams_end, "", text_encoded, flags=re.DOTALL)

        der_encoded, _marker, enc_flag = PEM.decode(text_encoded, passphrase)
        if enc_flag:
            passphrase = None
        result = _import_der(der_encoded, passphrase, max_iteration_count, threads, max_memory)
        return result

    # SEC1
    if len(encoded) > 0 and encoded[0] in (0x02, 0x03, 0x04):
        return _import_public_der(encoded, curve_name=curve_name)
