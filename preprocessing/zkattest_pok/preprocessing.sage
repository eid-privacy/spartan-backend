###### NIST P256 - Snippet from neuromancer.sk
p_256_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
p256_field = GF(p_256_p)
p256_a = p256_field(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
p256_b = p256_field(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
p256 = EllipticCurve(p256_field, (p256_a, p256_b))
p256_G = p256(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
p256.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)
p256_scalar_field = GF(p256.order())

# ZKAttest reworked verification equation.
# Setup with values we use in zpk-pocs circuits
element_bitwidth = 32*8

issuer_pubkey_x = 0xbc6082ae8535435de2193b0c021bda6e9b36bb451b579e0dfee2624aac740ca2
issuer_pubkey_y = 0x46b999512d3f7b2b63013dafba4126d45896a82c9385d7bf0965da3e7ede0b8c
signature = 0xbad1f9c2860c0764df8ab13e3ab29fae515483a381bad9348bc947675fbdf8bb1c82c9f2b65517c72b0ed076a20fab5b1f2f37b967899cd6dd5422842679464a
credential_hash = 0xf581583f6a27862f727445b0f1e82329115ba561687282da4e0c2f62481856ef

mask_256 = (1 << element_bitwidth) - 1
signature_r = signature >> element_bitwidth # lives in the scalar field of p256
signature_s = signature & mask_256 # lives in the scalar field of p256

print(signature_r)
print(signature_s)

issuer_pubkey = p256(
    p256_field(issuer_pubkey_x),
    p256_field(issuer_pubkey_y)
)

# Compute signature verification as specified in ZKAttest section 6
s_inv = p256_scalar_field(signature_s).inverse()
r_inv = p256_scalar_field(signature_r).inverse()
z = signature_s * r_inv
R = credential_hash*s_inv*p256_G + signature_r*s_inv*issuer_pubkey

sig_verification = z*R - credential_hash*r_inv*p256_G

print(issuer_pubkey)
print(sig_verification)
assert(issuer_pubkey == sig_verification)
