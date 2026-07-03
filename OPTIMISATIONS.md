# Proposed Optimisations

Result of a code review focused on big wins, in particular around elliptic-curve
operations. Covers the app code (`spartan-backend/src`), the Noir circuits
(`circuits/`), and how the app uses spartan2 0.9.0. No code has been changed;
this document only proposes.

Estimated impact assumes the real workloads (`c0100`–`c0102`), where in-circuit
EC scalar multiplications dominate the constraint count and prover time scales
roughly linearly with the number of constraints (Hyrax commit MSMs + sumcheck).

## Answers to the three guiding questions

**Is there a flag to run EC operations in non-constant time?**
No — and there is nothing left to gain there. spartan2 0.9.0's native EC code is
already variable-time on every hot path: `add_mixed_vartime` in the Pippenger
buckets, signed-digit Pippenger MSM, wNAF-5 `vartime_scalar_mul`, and
precomputed `FixedBaseMul` window tables for the Hyrax blinding generator `h`
and small commitment keys (see `spartan2-0.9.0/src/provider/msm.rs`). The
halo2curves `asm` feature is x86_64-only, so it does nothing on Apple Silicon.
The native side is not where the time goes; the in-circuit gadgets are.

**Are some multiplications always with the same point, so precomputing its
doubles pays off?**
Yes — in-circuit. `c0102_signature_vanilla_equation` computes
`t256_msm([G], [s_inv])` where `G` is the compile-time-constant P-256
generator, yet `AllocatedPoint::scalar_mul`
(`spartan-backend/src/noir/synthesis/allocated_point.rs`) treats every base as
a variable point and pays for ~254 in-circuit doublings. Precomputing the
doubles (or window tables) of `G` as circuit *constants* is the single biggest
win — see proposal 1. On the native side spartan2 already does this
(`FixedBaseMul` tables for `h` and for commitment keys with ≤ 64 bases).

**Are there scalar multiplications with n, n+1, n+2 where adding the point
would be cheaper?**
Not found — neither in the app's gadgets nor in spartan2's hot paths
(`FixedBaseMul::precompute` already builds its tables by incremental
addition). The nearest analogues in this codebase are:
- the *chained* multiplications `t·(s⁻¹·G)` in c0102, which cost two full
  ladders where one ladder plus a cheap non-native modular multiplication
  would do (proposal 2), and
- the same scalar `s_inv` being bit-decomposed twice, once per `t256_msm`
  call (proposal 6).

## Ranked proposals

### 1. Fixed-base scalar multiplication for constant points (in-circuit)

**Impact: 2–4× fewer constraints per fixed-base scalar mul.**

`AllocatedPoint::scalar_mul` costs ~9–10 R1CS constraints per scalar bit
(incomplete add 3, conditional selects 2, incomplete double 4), i.e.
**~2,800 constraints per 256-bit multiplication**, plus ~256 booleanity
constraints for the bit decomposition.

When the base is a circuit constant (the generator `G` in c0102), all
`2^i·G` are known at synthesis time:

- *Minimal version*: drop every in-circuit doubling and conditionally add the
  constant `2^i·G` per bit. Constant coordinates enter the linear
  combinations as coefficients rather than allocated variables, so each
  iteration shrinks to ~5 constraints (~45% saving).
- *Windowed version*: signed 3–4-bit windows over tables of constant points.
  Selecting among constant points is nearly free (a few selector-bit product
  constraints per window), leaving ~64–85 additions total: **3–4× fewer
  constraints** than today.

Where: new `scalar_mul_fixed_base` in
`src/noir/synthesis/allocated_point.rs`, dispatched from `handle_msm`
(`src/noir/synthesis/blackbox/multi_scalar_multiplication.rs`) when the point
inputs are `FunctionInput::Constant`.

Note the incomplete-addition edge cases (acc = ±table entry) need the usual
treatment: signed digits and/or a random offset point that is subtracted at
the end.

### 2. Collapse chained ladders via one non-native modmul (c0102)

**Impact: c0102's EC cost drops from ~11k to roughly 2.5–3.5k constraints.**

`c0102` computes four full ladders: `sG = s⁻¹·G`, `sQ = s⁻¹·Q`,
`tsG = t·(sG)`, `rsQ = r·(sQ)`. The chains exist because P-256 scalar-field
arithmetic (mod n) is not native to the circuit field. Instead:

- compute `u₁ = t·s⁻¹ mod n` and `u₂ = r·s⁻¹ mod n` out-of-circuit as
  witnesses,
- verify each with one non-native modular-multiplication gadget
  (`u·s ≡ t (mod n)`, ~200–400 constraints including range checks),
- then do a *single* ladder per term: `u₁·G` (fixed base, cheap via
  proposal 1) and `u₂·Q` (variable base).

This is the standard trick for in-circuit ECDSA verification
(Crescent does the equivalent transformation).

### 3. Strauss–Shamir shared-doubling for `a·P + b·Q`

**Impact: ~35–40% off each two-term verification equation.**

c0101 and c0102 both end in an equation of the form `a·P + b·Q = R`. A shared
ladder (one doubling chain; per bit conditionally add `P`, `Q`, or `P+Q`)
removes one entire doubling chain compared to two independent `scalar_mul`
calls plus `ec_add`.

Prerequisite: `handle_msm` currently asserts single-point input
(`points.len() == 2` field elements). Supporting 2-point MSM opcodes lets the
Noir circuits express the equation as one `t256_msm([P, Q], [a, b])` and the
backend apply Shamir transparently. Composes with proposal 1 when one of the
bases is `G`.

### 4. Do Spartan setup once; drop the sanity verify from `prove()`

**Impact: removes one full setup and one full verification per run
(~50% of prove-path wall time based on `stats.txt`, where `spartan_verify`
≈ half of `spartan_proof`).**

Currently, per `run_proof_and_verification`:

- `prove()` (`src/nizk_prover.rs`) runs `SpartanSNARK::setup` — a full shape
  synthesis plus hash-to-curve derivation of all commitment generators — and
  then runs `proof.verify(&vk)` as a sanity check;
- `verify()` (`src/nizk_verifier.rs`) runs `SpartanSNARK::setup` *again* from
  scratch on the verifier circuit just to re-derive the same `vk`.

Proposal: perform setup once per circuit, pass/persist `(pk, vk)` (both are
`Serialize`; key a disk cache by a hash of the circuit artifact), and gate the
prover-side sanity `proof.verify` behind a debug flag.

### 5. Batch the witness-generation field inversions

**Impact: witness generation of a scalar mul becomes ~50–100× cheaper
(secondary to 1–3, since constraint count dominates proving).**

Every ladder step's witness closure calls `.invert()`
(`add_incomplete`, `double_incomplete` in `allocated_point.rs`): ~512 full
field inversions (~300 muls each) per scalar multiplication, per synthesis
pass. Fix: compute the whole ladder natively first (projective coordinates,
one batched Montgomery inversion to normalize all points), then feed the
precomputed coordinates into the allocation closures.

### 6. Reuse scalar bit decompositions

**Impact: ~256 constraints saved per reused scalar.**

`s_inv` in c0102 feeds two `t256_msm` calls and is decomposed to bits twice.
Cache `to_bits_le` results per witness index across blackbox calls (e.g. in
`BlackboxRouter` alongside the allocation store).

### 7. Free build & conversion wins

- No `[profile.release]` tuning exists in `spartan-backend/Cargo.toml`. Add:

  ```toml
  [profile.release]
  lto = "fat"
  codegen-units = 1
  ```

  Typical 5–15% on ff-heavy code; keep `profile.profiling` inheriting it.
- `to_spartan_scalar_value` (`src/noir/scalar_conversion.rs`) converts every
  witness value via hex string → `BigUint` → *decimal string* →
  `from_str_vartime`. The byte-level `biguint_to_scalar` a few lines above is
  ~50× faster and already exists — use it (values are canonical, so only the
  modulus-embedding differences need care).

## Soundness observations (found along the way)

These are not performance items, but they affect the same code and should be
fixed before/while optimising:

- `allocate_or_get` (`src/noir/synthesis/blackbox/function_input.rs`)
  allocates ACIR *constants* as witness variables **without constraining them
  to the constant value** — a malicious prover can assign anything. Using
  constant linear combinations instead fixes soundness *and* removes
  allocations (and is what makes proposal 1 natural).
- `is_infinity` in `handle_msm` and `handle_ec_add` is allocated with value 0
  but never constrained; a prover can set it to 1 and route the gadgets
  through the infinity branches.
- `handle_msm` uses only `scalars[0]` (the low limb) and ignores the high
  limb. This is intentional for T-256/P-256 field sizes per the code comment,
  but the high limb should be constrained to 0 so a prover cannot smuggle
  values there.
