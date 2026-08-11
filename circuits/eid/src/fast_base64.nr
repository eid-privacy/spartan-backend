//! Lookup-free `base64url` encoder for fixed-size inputs.
//!
//! The standard `noir_base64`
//! encoder uses a 192-cell alphabet lookup table per output character, which
//! dominates the cost of circuits that base64-encode kilobyte-scale buffers
//! (e.g. c0200's full SD-JWT payload).
//!
//! This module emits the encoder as plain integer arithmetic over a
//! statically-unrolled loop, so every byte access is a *constant* array
//! index and resolves to a direct witness reference rather than a memory
//! op. Per 3-byte chunk we pay only the bit decomposition (a few u8 div /
//! mod ops) plus four 6-bit -> ASCII conditional selects.
//!
//! The encoder is **not padded** (URL-safe, no `=`) and matches RFC-4648
//! sec. 5 ("base64url"). Output length is `ceil(in_len * 4 / 3)`.

/// Map a 6-bit value to its base64url ASCII character.
///
/// Soundness: `v` is assumed (and used as) a `u8` with `0 <= v < 64`. The
/// branches partition `[0, 64)` exhaustively and disjointly:
///
/// - `v <  26`  -> `'A' + v`           (uppercase, 65..90)
/// - `v <  52`  -> `'a' + (v - 26)`    (lowercase, 97..122)
/// - `v <  62`  -> `'0' + (v - 52)`    (digit,    48..57)
/// - `v == 62`  -> `'-'` (45)
/// - else        -> `'_'` (95)
pub fn u6_to_ascii_url(v: u8) -> u8 {
    if v < 26 {
        v + 65
    } else if v < 52 {
        v + 71 // = v - 26 + 97
    } else if v < 62 {
        v - 4 // = v - 52 + 48
    } else if v == 62 {
        45
    } else {
        95
    }
}

/// Encode `input[..in_len]` to base64url, writing the resulting characters
/// into `out` starting at `out_offset`. The caller guarantees:
///
/// - `IN_LEN` is a multiple of 3 (input array is sized for whole 3-byte
///   chunks; pad the last bytes with zero if needed),
/// - `out` has at least `out_offset + (IN_LEN * 4) / 3` bytes,
/// - `in_len <= IN_LEN`.
///
/// Returns the effective output length `ceil(in_len * 4 / 3)`. The returned
/// length only depends on `in_len`; bytes beyond it in `out` are still
/// written but should be ignored.
///
/// The encoder always processes all `IN_LEN / 3` chunks so the constraint
/// shape is fixed and independent of `in_len`. For each 3-byte chunk
/// (b0, b1, b2) we emit:
///
/// ```text
///   v0 = b0 >> 2
///   v1 = ((b0 & 3) << 4) | (b1 >> 4)
///   v2 = ((b1 & 15) << 2) | (b2 >> 6)
///   v3 = b2 & 63
/// ```
///
/// each translated to ASCII via [`u6_to_ascii_url`].
pub fn encode_url_into<let IN_LEN: u32, let OUT_LEN: u32>(
    input: [u8; IN_LEN],
    in_len: u32,
    out: &mut [u8; OUT_LEN],
    out_offset: u32,
) -> u32 {
    // Number of 3-byte input chunks, rounded up so the final partial chunk
    // (if any) is still processed.
    let num_chunks: u32 = (IN_LEN + 2) / 3;
    for c in 0..num_chunks {
        let i0 = c * 3;
        // The `i0 + k < IN_LEN` predicates are compile-time constants because
        // both `i0` (loop-unrolled) and `IN_LEN` (generic) are known at
        // monomorphization. Noir prunes the dead branches, so each chunk's
        // accesses become static witness references -- never a memory op.
        let b0 = if i0 < IN_LEN { input[i0] } else { 0 };
        let b1 = if i0 + 1 < IN_LEN { input[i0 + 1] } else { 0 };
        let b2 = if i0 + 2 < IN_LEN { input[i0 + 2] } else { 0 };

        // Pure arithmetic decomposition of the 24 input bits into 4 6-bit
        // values. We avoid bitwise `&`, `|`, `<<`, `>>` because
        // BLACKBOX::AND is not supported by the spartan2 backend. For
        // disjoint bit-ranges in u8, `a | b` is equivalent to `a + b`.
        let b0_hi = b0 / 4; // top 6 bits of b0 (bits 2..7)
        let b0_lo = b0 - b0_hi * 4; // low 2 bits of b0
        let b1_hi = b1 / 16; // top 4 bits of b1
        let b1_lo = b1 - b1_hi * 16; // low 4 bits of b1
        let b2_hi = b2 / 64; // top 2 bits of b2
        let b2_lo = b2 - b2_hi * 64; // low 6 bits of b2

        let v0 = b0_hi;
        let v1 = b0_lo * 16 + b1_hi;
        let v2 = b1_lo * 4 + b2_hi;
        let v3 = b2_lo;

        let o = out_offset + c * 4;
        out[o] = u6_to_ascii_url(v0);
        out[o + 1] = u6_to_ascii_url(v1);
        out[o + 2] = u6_to_ascii_url(v2);
        out[o + 3] = u6_to_ascii_url(v3);
    }
    (in_len * 4 + 2) / 3
}

#[test]
fn test_u6_to_ascii_url_boundaries() {
    assert(u6_to_ascii_url(0) == 65); // 'A'
    assert(u6_to_ascii_url(25) == 90); // 'Z'
    assert(u6_to_ascii_url(26) == 97); // 'a'
    assert(u6_to_ascii_url(51) == 122); // 'z'
    assert(u6_to_ascii_url(52) == 48); // '0'
    assert(u6_to_ascii_url(61) == 57); // '9'
    assert(u6_to_ascii_url(62) == 45); // '-'
    assert(u6_to_ascii_url(63) == 95); // '_'
}

#[test]
fn test_encode_url_known_vector() {
    // "Many hands make light work." -> "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"
    let input: [u8; 27] = [
        77, 97, 110, 121, 32, 104, 97, 110, 100, 115, 32, 109, 97, 107, 101, 32, 108, 105, 103,
        104, 116, 32, 119, 111, 114, 107, 46,
    ];
    let expected: [u8; 36] = [
        84, 87, 70, 117, 101, 83, 66, 111, 89, 87, 53, 107, 99, 121, 66, 116, 89, 87, 116, 108,
        73, 71, 120, 112, 90, 50, 104, 48, 73, 72, 100, 118, 99, 109, 115, 117,
    ];
    let mut out: [u8; 36] = [0; 36];
    let n = encode_url_into(input, 27, &mut out, 0);
    assert(n == 36);
    for i in 0..36 {
        assert(out[i] == expected[i]);
    }
}
