# Experiment Background

This repo contains an SD-JWT experiment. The SD-JWT (credential) is produced by a Python script and consumed by the Noir circuits.
The script `create-prover.py` sets up the specific credential structure used in the
SICPA backend, which includes the public key of the issuer in the SD-JWT header.
This is different from the Swiyu-SD-JWT, which has a generic header, and a Web3-DID
in the body of the SD-JWT.
If you have devbox installed, you can create a new SD-JWT which will be written
to Prover.toml:

```bash
devbox shell
# inside devbox:
python3 create-prover.py
```

Once the Prover.toml is written, you can use the scripts from the `zkp-pocs/noir/scripts`
directory to run all benchmarks.

# Signature verification (Crescent + vanilla equation)

This circuit does **not** use Noir's built-in `std::ecdsa_secp256r1::verify_signature`.
Instead, following `c0200_swiyu_jwt`, it verifies:

- the **issuer JWT signature** with the "vanilla equation" style (cf.
  `c0102_signature_vanilla_equation`), consuming precomputed `R_jwt_x/y` and
  `s_inv_jwt` (private), and
- the **device signature** on `challenge_nonce` with the "Crescent" style (cf.
  `c0100_holder_binding_crescent_style`), consuming the precomputed public triple
  `R_dev_x/y`, `T_dev_x/y`, `U_dev_x/y`.

These precomputed witnesses cannot (cheaply) be derived in-circuit, so after
running `create-prover.py` you must run the off-circuit preprocessor to inject
them into `Prover.toml` and to (re)generate `verifier_input.json`:

```bash
cd ../../preprocessing/c0201_sicpa_backend
cargo run --release
```

The end-to-end flow is therefore: `create-prover.py` → preprocessor →
`nargo-t256 execute` (and prove/verify with the spartan backend).

# Why `ENCODED_HEADER_LEN` is a compile-time constant

`src/constants.nr` pins `ENCODED_HEADER_LEN: u32 = 88` and `main` takes the
header as a fixed-size array, so the base64url payload is written into
`signing_input_storage` at the **constant** offset `ENCODED_HEADER_LEN + 1`.
This is not cosmetic. Making that offset a witness — as
`c0201_sicpa_backend` does, where the header is a variable-length
`BoundedVec` and the offset is `header_len + 1` — inflates the circuit by more
than an order of magnitude. This section records why, and what to do if a
variable-length header ever becomes unavoidable.

## The mechanism: witness indices turn arrays into ACIR memory blocks

Noir's ACIR generation represents an array in one of two ways:

- **`AcirValue::Array`** — each element is its own witness. A constant-index
  read or write is a compile-time SSA rebind and costs *nothing*.
- **`DynamicArray`** — a real memory block, accessed via `MemoryInit` /
  `MemoryOp` opcodes.

A *single* access with a non-constant index converts the array to the second
form, and **the conversion is sticky**: every later access to that array —
including compile-time-constant ones — is emitted as a `MemoryOp`.

Our backend lowers each `MemoryOp` with a selector scan (see the module doc of
`spartan-backend/src/noir/synthesis/memory.rs`): for a block of length `N` it
allocates `N` boolean selectors plus `Σ sᵢ = 1` and `Σ i·sᵢ = index`, then one
gate per cell (`(value − cell)·s = new_cell − cell` for writes, `tᵢ = sᵢ·cellᵢ`
plus a sum for reads). That is **~2N constraints and ~2N aux witnesses per
access**. Since `eid::fast_base64::encode_url_into` performs one write per
output byte, a witness `out_offset` makes the encoder **O(OUT_LEN²)**.

## Measurements

Measured with `spartan-backend <dir> -c` on a scratch circuit: 96-byte input,
257-byte destination buffer (so `N = OUT_LEN = 257`, 128 encoder writes), with
every output byte folded into an asserted checksum — see the measurement
caveat below.

| variant | R1CS constraints | ACIR opcodes | vs. constant |
|---|---|---|---|
| `encode_url_into(…, out, 129)` — constant offset | **6 534** | 5 094 | 1.0× |
| `encode_url_into(…, out, off)` — witness offset | **206 215** | 5 988 | **31.6×** |
| encode at 0, then log-depth shift (below) | **10 307** | 6 459 | 1.6× |

The middle row's 199 681-constraint excess decomposes exactly as the cost
formula predicts: 128 writes × 538 (`≈ 2N + 2`) = 68 864, plus 257 reads × ~510
= ~131 000 — because the buffer is read back byte-by-byte afterwards.

That second term is the important one:

1. **The reads hurt more than the writes.** Stickiness means the read-back is
   billed at memory-op prices even though every one of those indices is a
   compile-time constant. Isolated: a circuit costing **3** constraints becomes
   **134 156** after *one* witness-index write followed by 257 constant-index
   reads. Extrapolated to `c0201`'s real buffer (`N = 2 861`),
   `sha256_var(signing_input_storage, …)` alone costs roughly
   `2 861 · 2·2 861 ≈ 16M` constraints, on top of ~15M for the encoder's
   writes. (Extrapolation only — synthesising that shape needs tens of GB.)
2. **A single stray line is enough.** In `c0201`,
   `signing_input_storage[header_len] = ASCII_DOT` is already a witness-index
   write. Even with a constant encoder offset, that one line poisons the buffer
   for every subsequent `sha256_var` read.

**Do not use `nargo info` to judge this.** A `MemoryOp` is *one* ACIR opcode,
so the ACIR column above ranks the variants in the *wrong order*: the witness
offset (5 988) looks cheaper than the shifter (6 459), while its real cost is
20× higher. Always measure with `spartan-backend -c`.

**Measurement caveat: observe the whole buffer.** Noir's dead-code elimination
prunes mux networks whose outputs nothing depends on, but it cannot prune
`MemoryOp`s. A scratch circuit that only asserts on `out[N-1]` therefore
flatters the shifter and not its rival — it reported 7 111 instead of 10 307
here, and made per-layer cost look sublinear in `LOG`. Fold every output byte
into an asserted value (or feed the buffer to `sha256_var`, as the real circuit
does) before believing any number.

## If a variable-length header becomes necessary

Keep witness indices away from the big buffer entirely: build it with constant
indices only, then apply the variable placement with a **log-depth barrel
shifter** in which every index is a compile-time constant. The shift here is
bounded by `ENCODED_HEADER_MAX_LEN` (128), so 8 layers suffice — `LOG` tracks
the maximum shift, not `N`.

```noir
/// Shift `src` towards higher indices by a witness amount. Every array index
/// below is a compile-time constant, so `src` never becomes a memory block.
/// `LOG` must cover the maximum shift: shift <= 128 needs LOG = 8.
fn shift_right<let N: u32>(src: [u8; N], shift: u32) -> [u8; N] {
    let mut rest = shift;
    let mut cur = src;
    let mut step: u32 = 1;
    for _k in 0..LOG {
        let bit = rest % 2; // `%` / `/` rather than bitwise: no BLACKBOX::AND
        rest = rest / 2;
        let mut next: [u8; N] = [0; N];
        for i in 0..N {
            let from = if i >= step { cur[i - step] } else { 0 };
            next[i] = if bit == 1 { from } else { cur[i] };
        }
        cur = next;
        step *= 2;
    }
    assert(rest == 0, "shift out of range");
    cur
}
```

Cost is `O(N · log(max_shift))` with zero memory ops: 10 307 constraints in the
table above, i.e. 1.6× the constant-offset version and 20× cheaper than the
witness-offset one. The shifter's own share is 3 773 constraints for
`8 · 257 = 2 056` byte muxes, i.e. **~1.8 constraints per byte per layer**.
Verified byte-for-byte against `encode_url_into(…, out, o)` for
`o ∈ {0, 11, …, 121}` with `nargo test`.

Why this beats the obvious loop: `out[i + shift] = enc[i]` needs, for each of
`N` bytes, an `N`-wide one-hot selector to express "which cell" — `N` muxes of
width `N`, hence `O(N²)`, even though the whole permutation is determined by
just `log₂(max_shift)` bits of witness. The barrel shifter matches that
entropy: it factors an arbitrary shift into `log₂(max_shift)` *fixed* shifts,
and each layer applies its fixed shift to all `N` bytes under **one shared
selector bit**. So the selector cost falls from `N · N` bits to `log₂(max_shift)`
bits, and every index becomes a compile-time constant — which is what keeps the
array out of a memory block and stops the poisoning of downstream reads.

Bounding the shift is what makes it cheap: with `shift ≤ 128` only 8 layers are
needed, regardless of `N` being 257 or 2 861 bytes.

The call site then becomes: put `'.'` at `enc[0]`, encode the payload at the
constant offset 1, `shift_right` by `header_len`, and finally overlay the
header over indices `0..ENCODED_HEADER_MAX_LEN` masked by `i < header_len`
(constant indices, ~2 constraints per byte over 128 bytes). Nothing
witness-indexed ever touches the buffer, so `sha256_var` stays cheap too.

Two cheaper alternatives, in preference order:

1. **Keep the length constant** — what this circuit does. `encoded_header` is a
   *public* input anyway, so pinning its encoded length costs nothing. It only
   works while the issuer's `kid` / DID yields a stable header length (88 bytes
   for the credentials `create-prover.py` currently emits).
2. **Dispatch over a small set of lengths.** With `k` candidate offsets, hoist
   the encoder out and select only the placement: `k · ENC_LEN` selects at ~1
   constraint each. Competitive with the shifter for small `k`, and simpler.

Longer term the fix belongs in the backend: `memory.rs` notes that the
selector encoding is a deliberate simple-first choice, and a
lookup-argument-based memory would remove this whole class of blow-up rather
than requiring each circuit to dodge it.
