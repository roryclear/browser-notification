from Crypto.Math.Numbers import Integer
from Crypto.Util._raw_api import SmartPointer, VoidPointer, load_pycryptodome_raw_lib
from _curve import _Curve

def curve25519_curve():
    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED  # 2**255 - 19
    order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

    _curve25519_lib = load_pycryptodome_raw_lib(
        "Crypto.PublicKey._curve25519",
        """
typedef void Point;

int curve25519_new_point(Point **out,
                         const uint8_t x[32],
                         size_t modsize,
                         const void* context);
int curve25519_clone(Point **P, const Point *Q);
void curve25519_free_point(Point *p);
int curve25519_get_x(uint8_t *xb, size_t modsize, Point *p);
int curve25519_scalar(Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
int curve25519_cmp(const Point *ecp1, const Point *ecp2);
""",
    )

    class EcLib:
        new_point = _curve25519_lib.curve25519_new_point
        free_point = _curve25519_lib.curve25519_free_point

    curve25519 = _Curve(
        Integer(p),
        None,
        Integer(order),
        Integer(9),
        None,
        None,
        255,
        "1.3.101.110",  # RFC8410
        None,
        "Curve25519",
        None,
        EcLib,
        None,
    )
    return curve25519


def curve448_curve():
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 2**448 - 2**224 - 1
    order = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3

    lib = """
typedef void Curve448Context;
typedef void Curve448Point;

int curve448_new_context(Curve448Context **pec_ctx);
void curve448_free_context(Curve448Context *ec_ctx);
int curve448_new_point(Curve448Point **out,
                       const uint8_t *x,
                       size_t len,
                       const Curve448Context *ec_ctx);
void curve448_free_point(Curve448Point *p);
int curve448_clone(Curve448Point **P, const Curve448Point *Q);
int curve448_get_x(uint8_t *xb, size_t modsize, const Curve448Point *p);
int curve448_scalar(Curve448Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed);
int curve448_cmp(const Curve448Point *ecp1, const Curve448Point *ecp2);
"""

    _curve448_lib = load_pycryptodome_raw_lib("Crypto.PublicKey._ec_nat", lib)

    class EcLib:
        new_context = _curve448_lib.curve448_new_context
        free_context = _curve448_lib.curve448_free_context
        new_point = _curve448_lib.curve448_new_point
        free_point = _curve448_lib.curve448_free_point

    curve448_context = VoidPointer()
    EcLib.new_context(curve448_context.address_of())

    curve448 = _Curve(
        Integer(p),
        None,
        Integer(order),
        Integer(5),
        None,
        None,
        448,
        "1.3.101.111",  # RFC8410
        SmartPointer(curve448_context.get(), EcLib.free_context),
        "Curve448",
        None,
        EcLib,
        None,
    )

    return curve448