# Experiment Background

This is based on [c0201_sicpa_backend](../c0201_sicpa_backend) and 
experiments how to keep variable-length header witnesses with a reasonable
constraint size.

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

# Long term fix

Longer term the fix belongs in the backend: `memory.rs` notes that the
selector encoding is a deliberate simple-first choice, and a
lookup-argument-based memory would remove this whole class of blow-up rather
than requiring each circuit to dodge it.

https://github.com/eid-privacy/spartan-backend/issues/59
