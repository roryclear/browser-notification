class _Curve:
    def __init__(
        self, p, b, order, Gx, Gy, G, modulus_bits, oid, context, canonical, openssh, rawlib, validate=None
    ):
        self.p = p
        self.b = b
        self.order = order
        self.Gx = Gx
        self.Gy = Gy
        self.G = G
        self.modulus_bits = modulus_bits
        self.oid = oid
        self.context = context
        self.canonical = canonical
        self.openssh = openssh
        self.rawlib = rawlib
        self.validate = validate