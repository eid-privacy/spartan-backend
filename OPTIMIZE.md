# Constraint-count regression from the RANGE fix (Finding #03)

Investigation into the prover slowdown reported after commit `936c819`
("fix: Finding #03 - Unconstrained bit values in RANGE"), and what was done
about it. Scope: `c0200_swiyu_jwt` and `c0203_sicpa_backend_move` (the two
SD-JWT/SICPA circuits that use `eid::fast_base64`).

## Root cause of the fix's cost

Before `936c819`, `eid::fast_base64::field_into_allocated_bits_le` allocated
each "bit" of a RANGE-checked value as a plain `AllocatedNum` with **no
constraint** forcing it to be 0 or 1. The only check was that
`Σ bit_i·2^i == value` — a malicious prover could assign *any* field element
to each "bit" and still satisfy that single linear equation, bypassing the
range check entirely. Since ACIR's `RANGE` opcode backs almost every
`u8`/`u32`/`bool` type-safety check Noir emits, this meant most integer
bounds in these circuits were previously unenforced.

The fix switches to `bellpepper_core::boolean::AllocatedBit::alloc`, which
adds exactly one `b·(1-b)=0` constraint per bit — already the theoretical
minimum for a sound bit-decomposition range check in plain R1CS (no lookup
argument available in spartan2 0.9.0). There is no cheaper correct
alternative purely inside `range.rs`.

## Why a "modest" constraint increase caused a big slowdown

Spartan2's `R1CSShape` pads `num_cons` to the next power of two
(`r1cs/mod.rs:853`, `num_cons_padded = num_cons.next_power_of_two()`). A
circuit sitting just below a power-of-two boundary gets hit twice: the raw
constraint increase from the fix, *and* a full doubling of the padded
constraint count (and thus ~2x prover time) if that increase crosses the
boundary.

Verified directly by checking out the pre-fix `range.rs` on top of current
`HEAD` and re-measuring with `spartan-backend -c <circuit_dir>`
(`--count-constraints`):

| Circuit | Pre-fix | Pre-fix padded | Post-fix (before this session) | Post-fix padded |
|---|---|---|---|---|
| `c0200_swiyu_jwt` | 1,941,180 | **2,097,152 (2²¹)** | 2,354,942 | **4,194,304 (2²²)** |
| `c0203_sicpa_backend_move` | 2,222,170 | 4,194,304 (2²²) | 2,682,898 | 4,194,304 (2²²) |

`c0200_swiyu_jwt` is the circuit that matches the original report: a ~21%
raw increase that tipped it from just under 2²¹ to just over it, doubling
the padded proof size. `c0203` was already past 2²¹ before the fix, so for
that one the fix added real cost without changing the padding bucket.

**All further work in this session targeted `c0200_swiyu_jwt`**, since it's
the one case where a moderate cut can actually drop a whole power-of-two
bucket.

## Where the constraints actually go

Measured via isolated micro-benchmarks (scratch Noir packages depending on
`eid`, built and measured with `spartan-backend -c`, deleted after use) and
via `nargo info` combined with the real RANGE-opcode histogram:

- `eid::fast_base64::encode_url_into` on a 2048-byte payload alone costs
  **446,645 constraints** — bigger than the entire RANGE-fix-driven increase
  on the rest of the circuit combined. Breakdown: ~112K from the per-chunk
  `/`/`%` byte-splitting (6 divisions × ~683 chunks), ~284K from
  `u6_to_ascii_url`'s three `<` comparisons × 2732 calls.
- The standard, lookup-table-based `BASE64_URL_ENCODER::encode_var` is
  **not** a cheaper alternative: measured at **1,265,639 constraints** for
  the same payload — nearly 3x worse than `fast_base64`. Don't switch to it.
- `move_right` (the log-depth barrel shifter in `eid::lib`) is already the
  right pattern (constant indices only, O(N·log(max_shift))) — nothing to
  improve there.

## What was applied (2 commits on `fix/security-mitigations`)

### Commit 1 — `perf(c0200): narrow length/offset types to u16 and tighten credential-size constants`

- `eid::fast_base64::encode_url_into`: `in_len` (and the returned encoded
  length) narrowed `u32` → `u16`. Every RANGE check backing a `<` comparison
  is sized to the wider of its operands' declared types; since
  `PAYLOAD_MAX_LEN` is always far below 2¹⁶, this halves the cost of the
  per-chunk `i0 + k < in_len` comparisons. `c0201`/`c0202`/`c0203` updated to
  match the new signature (pure type-compatibility change, no logic change
  there).
- `c0200_swiyu_jwt`: `dob_sd_offset`/`x_offset` narrowed to `u16` for the
  same reason.
- `c0200_swiyu_jwt/constants.nr` tightened to the actual minimum the real
  credential needs: `DOB_SALT_MAX_LEN` 32→22 (a 16-byte/128-bit salt is the
  standard SD-JWT salt size, base64url-encodes to exactly 22 chars),
  `DOB_VALUE_MAX_LEN` 16→10 (`birth_date_as_int` only ever reads indices
  0–9 of a fixed `"YYYY-MM-DD"` layout — anything above 10 was always dead
  capacity), `DISCLOSURE_MAX_LEN` 128→52 (now computed as
  `20 + DOB_SALT_MAX_LEN + DOB_VALUE_MAX_LEN`).
- **`PAYLOAD_MAX_LEN` (1911) was deliberately left untouched.** It already
  matches the embedded test credential byte-for-byte, and can't go lower:
  this is a real SD-JWT signed by the Swiyu demo issuer (see the circuit's
  own README) — only the issuer's *public* key is available here, so no
  smaller payload can be produced with a still-valid signature.

Result: **2,354,942 → 2,208,757 constraints (−6.2%)**, still padded to 2²².

### Commit 2 — `perf(c0200): replace [u8; 32] point coordinates with Field`

`R_jwt_x/y`, `issuer_pub_x/y`, `T_dev_x/y`, `U_dev_x/y` were `[u8; 32]`
ABI inputs only ever consumed via `Field::from_be_bytes(...)`. The byte
array bought nothing but 32 mandatory per-byte RANGE checks each (that's
exactly the cost the Finding #03 fix made real) — a `Field` input needs
none, since every field element is already canonical mod *p* by
construction of the proving system.

`_R_dev_x`/`_R_dev_y` had to stay `[u8; 32]`: that pair is genuinely unused
in-circuit (carried only for the verifier's off-circuit bookkeeping), and a
totally-unread `Field` input has no opcode referencing it at all — the
backend's precommitted-witness allocation can't compute an assignment for a
witness nothing defines (`"Unable to allocate precommitted variables:
an assignment for a variable could not be computed"`). The mandatory
per-byte RANGE checks on `[u8; 32]` incidentally give the synthesizer
something to allocate; there was no clean way found to force a reference
without an artificial no-op usage, which wasn't worth it for ~512
constraints.

Also extended `verifier_input.json` parsing
(`spartan-backend/src/noir/circuit_reader/verifier_input_mapping.rs`) to
accept a `"0x..."` hex string for single-wire `Field` inputs, matching the
convention `Prover.toml` already uses — there was previously no way to give
a large (>u64) public `Field` input a concrete value in that JSON format at
all, which this conversion's `--count-constraints` testing needs. Only
activates for arity-1 string values starting with `"0x"`; verified no other
circuit's `verifier_input.json` is affected.

Result: **2,208,757 → 2,206,198 constraints (−0.1%)**.

### Combined effect

```
2,354,942 → 2,206,198 constraints  (−6.3%)
padded: 4,194,304 (2²²) both before and after
```

Still **109,106 constraints short** of dropping back to 2²¹ (2,097,152).
The cheap, safe, mechanical wins are exhausted for this circuit.

## What was tried and did NOT work

Worth recording so it isn't re-attempted the same way:

Rewrote `fast_base64`'s byte-splitting + ASCII mapping to decompose bytes
into bits once (`to_be_bits`) and derive the three `<` comparisons via
boolean logic on shared bits, instead of repeated `/`, `%`, `<`. Result:
**479,466 constraints — 7% *worse*** than the original div/mod-based
version, not better.

Root cause (confirmed via micro-benchmarks, stored to the local `cq`
knowledge store): in this Noir version (1.0.0-beta.26 / nargo-t256 fork),
chaining `constant * (bool as u8)` terms into a running sum
(`32*b0+16*b1+...`) re-triggers a full 8-bit RANGE check at *every*
multiply-then-add step, even though the intermediate values are provably
tiny. Plain addition of two same-typed values is free; a lone multiply by a
constant is free; combining them isn't. The original div/mod-based code
apparently retains narrower implicit bounds through Noir's optimizer that
bit-cast reconstruction doesn't. Separately: casting a `Field` back down to
a narrow int type (`field_value as u8`) when the compiler can't prove
smallness costs a near-full-field-width range check (~248 bits observed),
not 8 — never do this to "finish" a bit-recomposition.

This means closing the remaining ~109K gap is **not** a quick Noir-source
trick; it needs either deeper ACIR/optimizer-level work, or a structural
change to the backend.

## Session 2: isolating the ASCII-mapping comparisons

Follow-up, focused purely on `u6_to_ascii_url`'s three `<` comparisons (the
~284K-constraint piece), to check whether the earlier negative result (bit
decomposition + boolean recombination, 7% worse) was actually caused by the
*byte-splitting* half of that rewrite rather than the ASCII-mapping half —
the two were only ever measured together.

Methodology: isolated micro-benchmarks, same as session 1 (throwaway Noir
package under `circuits/`, `verifier_input.json` with `null` private inputs
for shape-only counting, measured via `spartan-backend --count-constraints`,
deleted after use). All numbers are per-element marginal cost over a
2732-element loop, after subtracting the mandatory per-u8-ABI-input RANGE
check + addition baseline (measured at **19.0 constraints/element**).

| Operation (marginal, per element) | Constraints |
|---|---|
| `v < 26` (native) | **21.0** |
| `v == 26` (native) | 12.0 |
| `v / 26` (native, non-power-of-2 divisor) | 19.0 |
| `v < 26` via hand-rolled boolean AND/OR/NOT chain over `(v as Field).to_be_bits::<6>()` | **40.1** |

Two things confirmed, both negative for further Noir-source optimization:

1. **Division by a non-power-of-two constant is not a free substitute for
   `<`.** `v / 26` costs the same as `v < 26` (both ~19-21/element over
   baseline) because Noir's unsigned-division codegen must itself assert
   `remainder < divisor` — i.e. it contains a same-width comparison
   internally. A restructuring of the branch selection from `<`-chains to
   `/`-and-`==`-chains (feasible since 26*2=52 lines up with the real
   boundaries) was *not* built out, because this measurement shows it can't
   help: the division's hidden comparison costs as much as the `<` it
   replaces.
2. **Boolean-logic comparisons over decomposed bits are ~2x worse than the
   native `<` operator, not just "worse when combined with the byte-splitting
   rewrite."** Isolated to a single `v < 26` test (no byte-splitting
   involved at all), the hand-rolled bit-AND/OR/NOT chain measured 40.1
   constraints/element vs. 21.0 for the native comparison — worse than the
   theoretical minimum of 1 constraint/bit would suggest, implying each
   `bool`-typed AND/OR/NOT in this backend costs more than one R1CS
   constraint (likely because every intermediate `Boolean` result needs its
   own booleanity constraint re-established, on top of the combine
   constraint). This rules out the hypothesis that session 1's "7% worse"
   result was an artifact of conflating two changes — the ASCII-mapping half
   alone is already a loser. The full `u6_to_ascii_url_v2` rewrite (3
   comparisons sharing a decomposed-bits prefix plus the final selects) was
   also built and constraint-measured end-to-end: **377,007** vs baseline
   **308,707** for the same 2732-call loop (+22%), confirming the isolated
   single-comparison result at full-function scale. Correctness was verified
   against the real `u6_to_ascii_url` for all 64 inputs before measuring, so
   this is a clean apples-to-apples comparison, not a buggy rewrite.

Net: **no change was made to `eid::fast_base64` or any circuit this
session.** The three `<` comparisons in `u6_to_ascii_url`, and the div/mod
byte-splitting, are confirmed to already sit at (or near) a real cost floor
for this backend absent a lookup argument — consistent with session 1's
conclusion, now with the ASCII-mapping half tested in isolation rather than
only in combination with the byte-splitting rewrite.

## Session 3: architecture review — every base64 call site, not just `encode_url_into`

Zoomed out from `fast_base64` itself to the whole base64 surface in the four
SD-JWT circuits (`c0200_swiyu_jwt`, `c0201_sicpa_backend`,
`c0202_sicpa_backend_constant`, `c0203_sicpa_backend_move` — all four share
byte-identical structure here). Each circuit has **four** base64 operations,
only one of which was ever migrated off `noir_base64`:

| # | Call | Purpose | Implementation |
|---|---|---|---|
| A | `eid::fast_base64::encode_url_into(payload, ...)` | Re-encode the raw JSON payload to base64url to rebuild the JWS signing input (`base64url(header).base64url(payload)`) whose SHA-256 is ECDSA-verified | **already fast_base64** |
| B | `BASE64_URL_ENCODER::encode_var(dob_disclosure)` | Encode the constructed `["salt","birth_date","value"]` JSON (≤52 bytes) before hashing it | still `noir_base64` |
| C | `BASE64_URL_ENCODER::encode(sha256_var(...))` | Encode the 32-byte disclosure digest to 43 base64 chars, compared against the literal text in the payload's `_sd` array | still `noir_base64` |
| D | `BASE64_URL_DECODER::decode(device_key_x_bytes)` | Decode the 43-char base64 "x" coordinate found in the payload's embedded JWK into 32 raw bytes, to get the device public key | still `noir_base64` |

`dob_salt` and `dob_value` themselves need **no** conversion: the prover
already supplies `dob_salt` pre-encoded (as the 22-char base64url ASCII text
that goes directly into the disclosure JSON) and `dob_value` as the raw
`"YYYY-MM-DD"` ASCII text — both are copied verbatim into
`build_dob_disclosure`, never base64-processed. So B/C/D are the only
remaining non-optimized conversions, and they're identical across all four
circuits (same line numbers, same logic, copy-pasted).

### Measured costs (isolated micro-benchmarks, same methodology as sessions 1-2)

| Operation | `noir_base64` (lookup-table) | `eid::fast_base64` equivalent | Ratio |
|---|---|---|---|
| B: encode ~52 bytes (`encode_var`) | 33,096 | 8,265 | **4.0x** |
| C: encode 32 bytes, fixed (`encode`) | 7,611 | 5,090 | **1.5x** |
| D: decode 43 base64 chars -> 32 bytes | 22,787 | *(no decoder in `eid` -- see below)* | - |

B and C are a drop-in library swap: `eid::fast_base64::encode_url_into`
already generalizes to any byte length via its `IN_LEN`/`in_len` parameters
(round `IN_LEN` up to the next multiple of 3, pass the real length as
`in_len`), exactly as it's already used for the full payload. No circuit
logic or ABI changes needed (implemented later this session — see
"Implemented" below).

### D is architecturally backwards relative to the rest of the circuit

`eid` has no base64 **decoder** at all (`fast_base64.nr` only exports
`encode_url_into`); D is the only decode operation anywhere in these
circuits, and it's also the only place where a credential-embedded value is
extracted by decoding payload text into bytes, rather than by encoding a
known/witnessed value and comparing ASCII text. Every other credential field
already follows the encode-and-compare pattern:

- The DOB disclosure digest (C) is produced by hashing then
  base64-**encoding**, then compared character-by-character against the
  payload text (`main.nr`'s `for i in 0..COORD_BASE64_LEN { assert(payload[...] == expected_digest[i]) }`)
  -- it is never decoded out of the payload.
- All ECDSA precompute coordinates (`R_jwt_x/y`, `issuer_pub_x/y`,
  `T_dev_x/y`, `U_dev_x/y`) are passed in directly as `Field` witnesses (see
  session 1, commit 2) rather than extracted from any encoded text.

The device public key (D) is the one holdout: it's decoded from the
payload's embedded JWK `"x"` field into raw bytes, then `Field::from_be_bytes`'d,
then used in the device-ECDSA equation. Flipping it to match the rest of the
circuit -- take `device_pub_x` as a direct `Field` witness (the prover
already effectively knows it, same as `T_dev_x`/`U_dev_x` today), base64url-
**encode** its bytes with `fast_base64`, and assert the result matches the
43-char slice of `payload_storage` at `x_offset` exactly the way the digest
check already does -- would let `eid::fast_base64::encode_url_into` cover D
too, eliminating `noir_base64`'s decoder (and the `BASE64_URL_DECODER` import)
entirely. Measured cost of the replacement (encode 32 bytes: 5,090, plus the
per-char compare loop, which is the same O(43) equality-assert pattern
already paid for the digest check) is well under D's current 22,787.

**Revised, better than the above**: rather than adding `device_pub_x` as a
new ABI `Field` input (which would need the off-circuit preprocessor to
supply it -- not located/audited this session), get the untrusted claim via
an `unconstrained fn` hint instead, computed purely from data already
private to the circuit (`payload`, `x_offset`):

```
unconstrained fn decode_coord_hint(coord_text: [u8; COORD_BASE64_LEN]) -> Field {
    // Safety: untrusted claim, constrained below by re-encoding and
    // comparing the result against `coord_text`.
    let decoded: [u8; 32] = noir_base64::BASE64_URL_DECODER::decode(coord_text);
    Field::from_be_bytes(decoded)
}
// ...
let x_field: Field = unsafe { decode_coord_hint(device_key_x_bytes) };
let x_bytes: [u8; 33] = { let b: [u8; 32] = x_field.to_be_bytes(); /* pad to 33 */ };
let mut reencoded: [u8; 44] = [0; 44];
let _ = encode_url_into(x_bytes, 32, &mut reencoded, 0);
for i in 0..COORD_BASE64_LEN { assert(reencoded[i] == device_key_x_bytes[i]); }
```

Why this works and is sound: in Noir, everything reachable from an
`unconstrained fn` (called via `unsafe { ... }`) runs on the Brillig VM, not
ACIR -- it generates **zero** R1CS constraints no matter what it does
internally, including calling an existing constrained library function like
`noir_base64::BASE64_URL_DECODER::decode` unmodified. The existing decoder's
expense (confirmed by reading its source: `BASE64_DECODE_BE_URL_TABLE[index]`
with `index` a *witness*, i.e. exactly the sticky-dynamic-array cost trap
from earlier cq findings) simply never gets synthesized. The claimed value
is then constrained the cheap way, identically to how the DOB digest (C) is
already checked: re-encode with `fast_base64` and assert ASCII equality
against the literal payload text -- a wrong hint cannot pass, since base64url
is injective on fixed-length byte arrays, so matching text uniquely
determines the decoded value. No ABI/preprocessor change needed at all: the
"hint" is derived entirely from data the circuit already has.

Measured end-to-end (hint + re-encode + 43-char compare, correctness
verified against a known vector first): **6,752 constraints**, vs.
`noir_base64::decode`'s 22,787 -- a 3.4x reduction, better than the
±5,090-without-compare-loop estimate above and with none of the ABI
complexity. This is the recommended fix for D.

### Net estimated opportunity (see "Implemented" below for what actually landed)

```
B:  33,096 -> 8,265   (-24,831)
C:   7,611 -> 5,090   ( -2,521)
D:  22,787 -> 6,752   (-16,035)   (unconstrained-hint approach, no ABI change)
-----------------------------------------------------------------------
~43,400 constraints/circuit, x4 circuits (c0200/c0201/c0202/c0203)
```

~43K is well short of the ~109K/circuit needed to drop `c0200` back under
2^21 (session 1), but it's a mechanical, already-numerically-validated,
low-risk cleanup -- B and C are a pure library swap, same semantics, no ABI
change; D needs the `unconstrained`-hint rewrite above but likewise no ABI
change -- that was simply never done when the payload encoder (A) was
migrated to `fast_base64`. Worth doing on its own merits even though it
doesn't single-handedly close the power-of-two gap.

### Implemented (follow-up, same session): all three, in a surprising order

B, C, and D were all applied, across all four circuits, as three separate
commits (`bf1d4f6`, `b61043b`, `1dd8d2c` on `fix/security-mitigations`).

**The commit order is C, then B -- the reverse of how they're numbered
above -- because of a Noir compiler quirk discovered while implementing
this.** Migrating B (`encode_var`) first, before C, produces a hard compile
error on C's still-present `BASE64_URL_ENCODER::encode` call:

```
bug: Brillig function call isn't properly covered by a manual constraint
  --> .../noir_base64/v0.5.0/src/encoder/to_be_radix.nr:17:27
   | let result = unsafe { to_be_radix_64_decomposition(bytes) };
   | This Brillig call's inputs and its return values haven't been
   | sufficiently constrained.
```

Isolated with a minimal repro (`sha256_var` output fed straight into
`BASE64_URL_ENCODER::encode`, nothing else in the package): this error fires
on `encode` alone, in total isolation, regardless of how its input is
produced or how fully its output is used (tried: direct ABI inputs,
BoundedVec-sourced lengths, full-array equality loops consuming all 43
output bytes -- none of it matters). It stops firing the instant *any*
`BASE64_URL_ENCODER::encode_var` call exists anywhere else in the same
compilation unit, even on completely unrelated dummy data. Conclusion:
`encode` and `encode_var` both bottom out in the same generic
`to_be_radix_64` Brillig primitive, and Noir's "is this Brillig call
sufficiently constrained" compiler check appears to track that primitive's
safety per-program (or per-monomorphization) rather than per-call-site --
one call-site's constraint usage can silence the checker for a different,
genuinely-less-constrained call-site elsewhere. This looks like a Noir
compiler bug/limitation, not anything-shaped in our code; stored to cq as a
version-specific gotcha. Practical upshot: migrate `encode` before
`encode_var` wherever both appear together, or migrate both in the same
commit -- never leave only `encode_var` in place after removing the last
`encode` call (or vice versa) without checking the other still compiles.

Each commit was verified to compile and pass the full existing test suite
(including `c0200`'s `test_sdjwt_verification`, which exercises the real
credential end-to-end: signature, disclosure digest, device key, and age
gate) before being committed. Real measured constraint counts on
`c0200_swiyu_jwt` (not micro-benchmarks -- the actual circuit):

```
baseline (session 1 end):  2,206,198
after C (digest encode):   2,202,094   (-4,104)
after B (disclosure encode): 2,179,823 (-22,271)
after D (unconstrained hint): 2,163,453 (-16,370)
-----------------------------------------------------------------------
total: 2,206,198 -> 2,163,453  (-42,745, -1.9%)
```

Close to the ~43,400/circuit estimated above (the small per-step deltas from
the isolated micro-benchmarks don't line up exactly with real-circuit deltas
-- expected, since the real circuit's DISCLOSURE_MAX_LEN differs by circuit,
52 for c0200 vs. 128 for c0201/c0202/c0203 -- but the direction and
magnitude both confirm the micro-benchmarks were representative). Still
padded to 2^22; this was never expected to close that gap alone (see
"Remaining options" below).

### Lookup tables: confirmed, again, not to help

This session's B/C/D numbers are a second, independent confirmation of
session 1's finding ("the standard lookup-table-based
`BASE64_URL_ENCODER::encode_var` is not a cheaper alternative... nearly 3x
worse") -- `noir_base64`'s encoder/decoder, which *is* the lookup-table
implementation, loses to `fast_base64`'s plain arithmetic by 1.5-4x across
every size tested (33-byte, 52-byte, and the original 2048-byte payload).
Root cause is structural, not an artifact of any one benchmark: spartan2
0.9.0 has no native lookup-argument primitive (Plookup/logUp-style), so a
"lookup table" written in Noir is not O(1) per access on this backend -- it
still costs O(table size) or O(bits), either as a witness-indexed memory op
(~2x table size per access, see the cq finding on dynamic-array stickiness)
or as a selector/decision-tree structure over the table's entries. Plain
arithmetic decomposition (what `fast_base64` does) avoids paying for a
64-entry (or 256-entry) table structure at all. This is very unlikely to
reverse for base64-sized alphabets without a real lookup argument in the
proving system itself (remaining option 1 below) -- don't re-try a lookup-
table-based encoder/decoder in this backend without one.

## Session 4: EC scalar-multiplication batching — investigated, not implemented

Follow-up question: the JWT ECDSA "vanilla equation" check in `main.nr`
computes `R_jwt = t*s_inv*G + r*s_inv*Q_iss` via four separate `t256_msm`
calls --

```
let sG_jwt = t256_msm([G], [s_inv_scalar_jwt]);        // s_inv * G
let sQ_jwt = t256_msm([Q_iss], [s_inv_scalar_jwt]);    // s_inv * Q_iss
let tsG_jwt = t256_msm([sG_jwt], [t_jwt]);             // t * (s_inv*G)
let rsQ_jwt = t256_msm([sQ_jwt], [r_jwt_scalar]);      // r * (s_inv*Q_iss)
```

-- raising the question of whether `t256_msm`'s `[P256Point; N]`/
`[T256Scalar; N]` signature (which *looks* like a real multi-scalar-mult
API) could batch several of these into one cheaper call, the way a true
Straus-Shamir MSM shares doubling steps across multiple scalar/point pairs.

### `t256_msm` is a backend blackbox, not a Noir gadget -- and only N=1 is implemented

`std::field::t256::t256_msm` compiles to a single ACIR
`#[foreign(multi_scalar_mul)]` opcode; its real cost is whatever
`spartan-backend`'s Rust synthesis code does with that opcode, not anything
visible in Noir source (found by extracting the embedded noir stdlib source
directly from the `nargo-t256` binary via `strings`, since this fork's
`std::field::t256` isn't distributed as separate `.nr` files on disk --
`field/t256.nr` ends up baked into the compiler binary like the rest of
noir_stdlib).

`spartan-backend/src/noir/synthesis/blackbox/multi_scalar_multiplication.rs`,
`handle_msm` (lines ~26-35):

```rust
assert_eq!(2, points.len(), "Only single point multiplication is supported");
assert_eq!(2, scalars.len(), "Only single point multiplication is supported");
```

Despite the generic `<let N: u32>` signature at the Noir level, this
backend's handler hard-asserts exactly one point (x, y = 2 field elements)
and one scalar (lo, hi = 2 field elements) -- `N` is always 1 in practice.
**Calling `t256_msm` with more than one point/scalar pair is not supported
today.** ACIR itself has no problem with it (`BlackBoxFuncCall::MultiScalarMul`
takes arbitrary-length `Vec<FunctionInput>`), so `nargo compile` would
succeed and produce a 4-point/4-scalar opcode for an N=2 call -- but
`spartan-backend` would then **panic** (a Rust `assert_eq!`, not a
recoverable synthesis error) the moment it tried to synthesize or
count-constraints on that circuit. Stored to cq as a gotcha: don't try an
N>1 `t256_msm` call expecting it to just work or fail gracefully.

### A real optimization is still sitting in the same function, already exploitable

`handle_msm` has a **fixed-base fast path** (lines ~58-91): when the base
point is a Noir-level compile-time constant, it uses
`AllocatedPoint::scalar_mul_fixed_base` (precomputed windows, no in-circuit
doublings) instead of the generic `point.scalar_mul` variable-base ladder
(~9-10 constraints/bit, ~2,500-3,000 total for a 256-bit scalar). Checking
the four calls above against this:

| call | base point | path taken |
|---|---|---|
| `s_inv * G` | `G` (`pub global`, literal constant) | **fixed-base, cheap** |
| `s_inv * Q_iss` | `Q_iss` (built from `pub Field` inputs) | variable-base, ~2,500-3,000 |
| `t * (s_inv·G)` | witness (prior MSM result) | variable-base, ~2,500-3,000 |
| `r * (s_inv·Q_iss)` | witness (prior MSM result) | variable-base, ~2,500-3,000 |

Only the `G` multiplication is cheap; the other three all pay the full
ladder. Since N>1 batching isn't available, the two chained multiplications
(`t * (s_inv*G)`, `r * (s_inv*Q_iss)`) can still be collapsed using the same
hint-and-cheaply-constrain shape as the base64 work above: compute
`u1 = t*s_inv mod n` and `u2 = r*s_inv mod n` **unconstrained**, constrain
each with a cheap non-native modular-multiplication check (~200-400
constraints each, vs. a full ~2,500-3,000-constraint ladder), then compute
`u1*G` (still fixed-base, still cheap) and `u2*Q_iss` (one variable-base
ladder instead of two chained ones) and add. Net: collapses "1 cheap + 3
expensive ladders" down to "1 cheap + 1 expensive ladder + 2 small modmul
checks" -- an estimated **~4,000-4,600 constraint** reduction. Not attempted
this session (per explicit request): it touches the ECDSA verification
equation itself, not a pure library swap, so it carries real soundness risk
if the modmul-check or the reduction-mod-n logic is subtly wrong, unlike the
base64 changes which preserved an identical input/output contract.

### The actual batching opportunity, if ever pursued

Implementing genuine N>1 support in `handle_msm` -- a real Straus-Shamir-style
shared-ladder gadget that interleaves one doubling with N conditional adds
per bit, instead of N independent ladders -- would benefit every circuit
using multiple MSM calls on independent points, not just `c0200`'s JWT
check. This is real protocol-level engineering on soundness-critical crypto
code inside `spartan-backend` (not a circuit change), with its own
correctness burden (must still reject off-curve/infinity edge cases per
point, as the existing single-point tests in
`multi_scalar_multiplication.rs` already cover for N=1). Flagged here as a
backend-level remaining option, deliberately not attempted.

## Remaining options (not attempted)

1. **Lookup-argument range-check primitive** (Plookup/logUp-style) in the
   Spartan2/vega_prover backend, replacing O(bits) boolean decomposition
   with O(1) amortized cost. Would help every circuit, not just `c0200`,
   but is real protocol-level engineering — spartan2 0.9.0 has no such
   primitive today.
2. **Deeper `fast_base64` core-loop rework**, informed by the negative
   result above — i.e. actually profiling which specific ACIR
   patterns Noir's optimizer does/doesn't elide range checks for, rather
   than guessing by analogy to `move_right`'s style.
3. **Real multi-point MSM support in `handle_msm`** (session 4) — a
   Straus-Shamir-style shared-ladder blackbox implementation, benefiting
   every circuit with multiple independent-point MSM calls, not just the
   hint-and-collapse trick available for `c0200`'s specific chained-scalar
   pattern.
4. **Hint-and-collapse the chained JWT-equation scalar multiplications**
   (session 4) — smaller, circuit-only, ~4,000-4,600 constraints on
   `c0200`, but touches ECDSA verification logic directly and needs careful
   soundness review before attempting.
5. Accept the 2²² bucket for `c0200` as the honest cost of both the
   soundness fix and the feature set, and optimize proving time by other
   means (see `OPTIMISATIONS.md` for a separate, EC-operation-focused
   review — unrelated to this investigation, not yet reconciled against
   these findings).

## Reproducing the measurements

```bash
# From spartan-backend/, in a devbox shell:
cargo build --release
./target/release/spartan-backend -c ../circuits/c0200_swiyu_jwt
```

To re-measure the pre-fix baseline: check out
`spartan-backend/src/noir/synthesis/blackbox/range.rs` from the parent of
commit `936c819` on top of current `HEAD`, rebuild, measure, then restore
with `git checkout HEAD -- spartan-backend/src/noir/synthesis/blackbox/range.rs`.

Isolated per-function constraint costs (e.g. "how much does
`encode_url_into` alone cost on an N-byte payload") were measured with
throwaway Noir packages under `circuits/` depending on `eid`, with a
`verifier_input.json` giving `null` for every private input (shape-only
counting doesn't evaluate values) — deleted after use, not committed.
