use std::field::t256::P256Point;

// Size of a T256 field element decomposed into bytes
pub global T256_SCALAR_SIZE: u32 = 32;

// P-256 (secp256r1) group order n. This circuit's native `Field` modulus is
// the P-256 *base* field p (see std::field::t256), a different, slightly
// larger modulus than n (p - n ~= 2^126, both close to 2^256). A SHA-256
// digest folded straight into `Field` arithmetic is only reduced mod p, not
// mod n, so it is not always a canonical P-256 scalar -- see
// `p256_scalar_from_digest` below.
global P256_ORDER: Field = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

// p - n, used to correct for the (~2^-32-probability) case where the raw
// digest is >= p and `Field::from_be_bytes` has already wrapped once.
global P256_BASE_MINUS_ORDER: Field = 0x4319055358e8617b0c46353d039cdaae;

// Big-endian, constant-index byte-array comparison (a >= b). Used to detect
// whether a raw digest is >= the native field modulus *before* it is folded
// into a `Field`, since a `Field` value alone can no longer distinguish "d"
// from "d - p" once the accumulation has wrapped.
fn be_bytes_ge(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut is_ge = true;
    let mut decided = false;
    for i in 0..32 {
        if !decided {
            if a[i] != b[i] {
                is_ge = a[i] > b[i];
                decided = true;
            }
        }
    }
    is_ge
}

// Reduces an arbitrary 32-byte value (e.g. a SHA-256 digest) modulo the
// P-256 group order n, producing a value safe to use as a `T256Scalar.lo`.
//
// `Field::from_be_bytes` alone is not enough here: it accumulates mod this
// circuit's native modulus p (the P-256 *base* field), not mod n, so for
// roughly 1 in 2^32 digests it silently wraps (giving d - p instead of d),
// and even when it doesn't wrap the result can still be >= n and therefore
// rejected by the T256 scalar-mul blackbox as a non-canonical scalar.
//
// Note: the `wrapped` check below must stay a raw byte-array comparison
// against the native modulus -- once `digest` is folded into a `Field` via
// `Field::from_be_bytes`, a value >= p has already been silently reduced to
// `d - p`, and there is no `Field`-level operation that can recover whether
// that happened. `Field::lt` is fine for the *second* comparison (`w` against
// `P256_ORDER`) because at that point `w` is always canonical mod p.
//
// Do NOT use this for P-256 point coordinates -- those are already < p by
// construction and should go through `Field::from_be_bytes` directly.
pub fn p256_scalar_from_digest(digest: [u8; 32]) -> Field {
    let p_bytes: [u8; 32] = std::field::modulus_be_bytes().as_array();
    let wrapped = be_bytes_ge(digest, p_bytes);
    let w = Field::from_be_bytes(digest);

    let reduced_no_wrap = if w.lt(P256_ORDER) { w } else { w - P256_ORDER };
    let reduced_wrapped = w + P256_BASE_MINUS_ORDER;

    if wrapped { reduced_wrapped } else { reduced_no_wrap }
}

mod tests {
    use super::p256_scalar_from_digest;

    // secp256r1 base field modulus p (this circuit's native `Field` modulus)
    // and group order n, as big-endian bytes, plus their immediate
    // neighbours. p256_scalar_from_digest must return `digest mod n` across
    // all six cases, exercising both the wraparound branch (>= p) and the
    // plain-subtraction branch (>= n but < p).
    global P_MINUS_1: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfe,
    ];
    global P: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    global P_PLUS_1: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    global N_MINUS_1: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x50,
    ];
    global N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    global N_PLUS_1: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x52,
    ];

    #[test]
    fn test_p_minus_1_reduces_to_p_minus_n_minus_1() {
        // p - 1 < p (no wraparound), but still >= n, so it needs a plain
        // subtraction: (p - 1) mod n == (p - n) - 1.
        assert_eq(
            p256_scalar_from_digest(P_MINUS_1),
            0x4319055358e8617b0c46353d039cdaad,
        );
    }

    #[test]
    fn test_p_reduces_to_p_minus_n() {
        // digest == p is the first wraparound value: Field::from_be_bytes
        // gives w == 0, and the fixup (w + (p - n)) must recover p mod n.
        assert_eq(p256_scalar_from_digest(P), 0x4319055358e8617b0c46353d039cdaae);
    }

    #[test]
    fn test_p_plus_1_reduces_to_p_minus_n_plus_1() {
        // Still in the wraparound branch: w == 1, fixup gives (p - n) + 1.
        assert_eq(
            p256_scalar_from_digest(P_PLUS_1),
            0x4319055358e8617b0c46353d039cdaaf,
        );
    }

    #[test]
    fn test_n_minus_1_is_unreduced() {
        // n - 1 < n, so it's already canonical and must be returned as-is.
        assert_eq(
            p256_scalar_from_digest(N_MINUS_1),
            0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550,
        );
    }

    #[test]
    fn test_n_reduces_to_zero() {
        // digest == n is the boundary of the plain-subtraction branch: n mod n == 0.
        assert_eq(p256_scalar_from_digest(N), 0);
    }

    #[test]
    fn test_n_plus_1_reduces_to_one() {
        assert_eq(p256_scalar_from_digest(N_PLUS_1), 1);
    }

    // Regression check for the Field::lt fix in the T256 toolchain: this used
    // to crash inside std::field::bn254's decompose/assert_gt_limbs with
    // "Assertion failed: call to assert_max_bit_size", because
    // compat::is_bn254() was hardcoded to `true`, forcing every Field::lt to
    // assume both operands are canonical mod the BN254 modulus (~2^254) even
    // though T256 field elements routinely exceed that bound.
    #[test]
    fn test_field_lt_on_large_t256_values() {
        let n_minus_1 = Field::from_be_bytes(N_MINUS_1);
        let n = Field::from_be_bytes(N);
        let n_plus_1 = Field::from_be_bytes(N_PLUS_1);
        let p_minus_1 = Field::from_be_bytes(P_MINUS_1);

        assert(n_minus_1.lt(n));
        assert(!n.lt(n_minus_1));
        assert(!n_plus_1.lt(n));
        assert(n.lt(n_plus_1));
        assert(n.lt(p_minus_1));
        assert(!p_minus_1.lt(n));
    }
}

// Enforce key ECDSA equation parameters to be in valid ranges
// Typically, > 0 and < n.
// From Noir's construction, `Field` variables are already reduced (mod n)
pub fn enforce_ecdsa_parameters(s_inv_jwt: Field, R_jwt: P256Point) {
    assert(not_zero(s_inv_jwt));
    assert(not_zero(R_jwt.x) & not_zero(R_jwt.y));
}

fn not_zero(x: Field) -> bool {
    !x.eq(0)
}
