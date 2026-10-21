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


def _seed_to_scalar(curve_id: int, seed: bytes) -> tuple[Optional[bytes], Integer]:
    """The prefix (EdDSA only) and the secret scalar of a seed.

    RFC 8032 (5.1.5 and 5.2.5) for Ed25519 and Ed448: the scalar comes from
    the hash of the seed. RFC 7748 (5) for X25519 and X448: the seed is the
    scalar. In both cases, the scalar is clamped (little endian).
    """

    prefix = None
    if curve_id == _CurveID.ED25519:
        seed_hash = SHA512.new(seed).digest()
        prefix, scalar = seed_hash[32:], bytearray(seed_hash[:32])
    elif curve_id == _CurveID.ED448:
        seed_hash = SHAKE256.new(seed).read(114)
        prefix, scalar = seed_hash[57:], bytearray(seed_hash[:57])
    else:
        scalar = bytearray(seed)

    if curve_id in (_CurveID.ED25519, _CurveID.CURVE25519):
        scalar[0] &= 0xF8
        scalar[31] = (scalar[31] & 0x7F) | 0x40
    else:
        scalar[0] &= 0xFC
        scalar[55] |= 0x80
        if curve_id == _CurveID.ED448:
            scalar[56] = 0
    return prefix, Integer.from_bytes(scalar, byteorder="little")


class UnsupportedEccFeature(ValueError):
    pass


class EccKey:
    r"""Class defining an ECC key.
    Do not instantiate directly.
    Use :func:`generate`, :func:`construct` or :func:`import_key` instead.

    :ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
    :vartype curve: string

    :ivar pointQ: an ECC point representing the public component.
    :vartype pointQ: :class:`EccPoint` or :class:`EccXPoint`

    :ivar d: A scalar that represents the private component
             in NIST P curves. It is smaller than the
             order of the generator point.
    :vartype d: integer

    :ivar seed: A seed that represents the private component
                in Ed22519 (32 bytes), Curve25519 (32 bytes),
                Curve448 (56 bytes), Ed448 (57 bytes).
    :vartype seed: bytes
    """

    def __init__(
        self,
        *,
        curve: Optional[str] = None,
        d: Optional[Union[int, Integer]] = None,
        seed: Optional[bytes] = None,
        point: Optional[Union[EccPoint, EccXPoint]] = None,
    ) -> None:
        """Create a new ECC key

        Keywords:
          curve : string
            The name of the curve.
          d : integer
            Mandatory for a private key one NIST P curves.
            It must be in the range ``[1..order-1]``.
          seed : bytes
            Mandatory for a private key on Ed25519 (32 bytes),
            Curve25519 (32 bytes), Curve448 (56 bytes) or Ed448 (57 bytes).
          point : EccPoint or EccXPoint
            Mandatory for a public key. If provided for a private key,
            the implementation will NOT check whether it matches ``d``.

        Only one parameter among ``d``, ``seed`` or ``point`` may be used.
        """

        curve_name = curve
        # Which of these attributes are set depends on the type of key
        self._d: Any = cast(Any, d)
        self._seed: Any = cast(Any, seed)
        self._point: Any = cast(Any, point)
        if curve_name is None and self._point:
            curve_name = self._point.curve

        if curve_name not in _curves:
            raise ValueError("Unsupported curve (%s)" % curve_name)
        self._curve = _curves[curve_name]
        self.curve = self._curve.canonical

        count = int(self._d is not None) + int(self._seed is not None)

        if count == 0:
            if self._point is None:
                raise ValueError("At lest one between parameters 'point', 'd' or 'seed' must be specified")
            return

        if count == 2:
            raise ValueError("Parameters d and seed are mutually exclusive")

        # NIST P curves work with d, the other curves with a seed
        seed_len = _SEED_LENGTHS.get(self._curve.id)
        if seed_len is None:
            if self._seed is not None:
                raise ValueError("Parameter 'seed' cannot be used with NIST P-curves")
            self._d = Integer(self._d)
            if not 1 <= self._d < self._curve.order:
                raise ValueError("Parameter d must be an integer smaller than the curve order")
            return

        if self._d is not None:
            raise ValueError("Parameter d can only be used with NIST P curves")
        if len(self._seed) != seed_len:
            raise ValueError(
                "Parameter seed must be %d bytes long for %s" % (seed_len, self._curve.canonical)
            )
        self._prefix, self._d = _seed_to_scalar(self._curve.id, self._seed)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EccKey):
            return False

        if other.has_private() != self.has_private():
            return False

        return other.pointQ == self.pointQ

    def __repr__(self) -> str:
        if self.has_private():
            if self._curve.is_edwards:
                extra = ", seed=%s" % binascii.hexlify(self._seed).decode("latin-1")
            else:
                extra = ", d=%d" % int(self._d)
        else:
            extra = ""
        if self._curve.id in (_CurveID.CURVE25519, _CurveID.CURVE448):
            x = self.pointQ.x
            result = "EccKey(curve='%s', point_x=%d%s)" % (self._curve.canonical, x, extra)
        else:
            x, y = self.pointQ.xy
            result = "EccKey(curve='%s', point_x=%d, point_y=%d%s)" % (self._curve.canonical, x, y, extra)
        return result

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

    # ECDSA
    def _verify(self, z, rs):
        order = self._curve.order
        sinv = rs[1].inverse(order)
        point1 = self._curve.G * ((sinv * z) % order)
        point2 = self.pointQ * ((sinv * rs[0]) % order)
        return (point1 + point2)._x % order == rs[0]

    @property
    def d(self) -> int:
        if not self.has_private():
            raise ValueError("This is not a private ECC key")
        return int(self._d)

    @property
    def seed(self) -> bytes:
        if not self.has_private():
            raise ValueError("This is not a private ECC key")
        return self._seed

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
        """Export this ECC key.

        Args:
          format (string):
            The output format:

            - ``'DER'``. The key will be encoded in ASN.1 DER format (binary).
              For a public key, the ASN.1 ``subjectPublicKeyInfo`` structure
              defined in `RFC5480`_ will be used.
              For a private key, the ASN.1 ``ECPrivateKey`` structure defined
              in `RFC5915`_ is used instead (possibly within a PKCS#8 envelope,
              see the ``use_pkcs8`` flag below).
            - ``'PEM'``. The key will be encoded in a PEM_ envelope (ASCII).
            - ``'OpenSSH'``. The key will be encoded in the OpenSSH_ format
              (ASCII, public keys only).
            - ``'SEC1'``. The public key (i.e., the EC point) will be encoded
              into ``bytes`` according to Section 2.3.3 of `SEC1`_
              (which is a subset of the older X9.62 ITU standard).
              Only for NIST P-curves.
            - ``'raw'``. The public key will be encoded as ``bytes``,
              without any metadata.

              * For NIST P-curves: equivalent to ``'SEC1'``.
              * For Ed25519 and Ed448: ``bytes`` in the format
                defined in `RFC8032`_.
              * For Curve25519 and Curve448: ``bytes`` in the format
                defined in `RFC7748`_.

          passphrase (bytes or string):
            (*Private keys only*) The passphrase to protect the
            private key.

          use_pkcs8 (boolean):
            (*Private keys only*)
            If ``True`` (default and recommended), the `PKCS#8`_ representation
            will be used.
            It must be ``True`` for Ed25519, Ed448, Curve25519, and Curve448.

            If ``False`` and a passphrase is present, the obsolete PEM
            encryption will be used. It derives the key with a single round
            of MD5, and is therefore easy to brute force: use it only with
            a high-entropy passphrase (like 16 random bytes), for
            compatibility with old software.

          protection (string):
            The encryption scheme used when a private key is exported with
            password-protection and PKCS#8 (both ``DER`` and ``PEM`` formats).
            For all possible protection schemes,
            refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
            The default is ``'PBKDF2WithHMAC-SHA256AndAES256-CBC'``.

          compress (boolean):
            If ``True``, the method returns a more compact representation
            of the public key, with the X-coordinate only.

            If ``False`` (default), the method returns the full public key.

            This parameter is ignored for Ed25519/Ed448/Curve25519/Curve448,
            as compression is mandatory.

          prot_params (dict):
            When a private key is exported with password-protection
            and PKCS#8 (both ``DER`` and ``PEM`` formats), this dictionary
            contains the  parameters to use to derive the encryption key
            from the passphrase.
            For all possible values,
            refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
            The defaults meet the OWASP recommendations (with the default
            ``protection``): there is no need to set them.

          randfunc (callable):
            (*Private keys only*)
            A function that returns random bytes, for the encryption
            (salt and IV). By default, :func:`Crypto.Random.get_random_bytes`.

          threads (integer):
            (*Private keys only*)
            The maximum number of threads used to derive the encryption key
            with scrypt (default: 1, no extra threads; 0 for all CPU cores).
            Only useful with PKCS#8, a scrypt ``protection`` and a
            ``parallelization`` larger than 1 in ``prot_params``.
            The output does not depend on the number of threads.

        .. warning::
            If you don't provide a passphrase, the private key will be
            exported in the clear!

        .. _PEM:        https://www.rfc-editor.org/rfc/rfc1421
        .. _`PEM encryption`: https://www.rfc-editor.org/rfc/rfc1423
        .. _OpenSSH:    http://www.openssh.com/txt/rfc5656.txt
        .. _RFC5480:    https://tools.ietf.org/html/rfc5480
        .. _SEC1:       https://www.secg.org/sec1-v2.pdf
        .. _RFC7748:    https://tools.ietf.org/html/rfc7748

        Returns:
            A multi-line string (for ``'PEM'`` and ``'OpenSSH'``) or
            ``bytes`` (for ``'DER'``, ``'SEC1'``, and ``'raw'``) with the encoded key.
        """

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

def _import_ed25519_public_key(encoded: bytes) -> tuple[Int, Int]: pass
def _import_curve25519_public_key(encoded): pass
def _import_curve448_public_key(encoded): pass
def _import_ed448_public_key(encoded: bytes) -> tuple[Int, Int]: pass


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
