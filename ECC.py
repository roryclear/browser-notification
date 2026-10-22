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
from Crypto.PublicKey._point import EccPoint, _curves

RNG = Callable[[int], bytes]
Int = Union[int, Any]

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
        blind = Integer.random_range(min_inclusive=1, max_exclusive=order)

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
