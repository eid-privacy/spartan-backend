# Bumping the noir/t256 fork version

This repo pins a fork of noir (`eid-privacy/noir`, "t256" branch family) across
three files. Bumping from one beta to the next (currently working through
beta_22 → beta_23 → beta_24 → beta_25 → beta_26) touches all three, plus
regenerated circuit artifacts. Do **one beta at a time**, never skip ahead —
each step gets its own commit so a regression can be bisected to a single
noir/nargo/barretenberg version.

## The three coupled identifiers

They always move together and must reference the *same* underlying noir
commit, but are spelled differently in each file:

1. **`devbox.json`** → `packages` array, three flake refs:
   - `github:eid-privacy/flakes#noir-versions.v1_0_0-beta_N`
   - `github:eid-privacy/flakes#barretenberg-versions.beta_N`
   - `github:eid-privacy/flakes#nargo-t256-versions.t256-v0_N` (sometimes with
     a trailing `-M` build suffix, e.g. `t256-v0_22-1` — the suffix is **not
     predictable from N alone**, see below)
2. **`spartan-backend/Cargo.toml`** → `tag = "t256-v0.N"` (or `t256-v0.N-M`)
   on exactly five git dependencies: `acir`, `acvm`, `noirc_abi`,
   `noirc_artifacts`, `noir_artifact_cli`. All five must use the identical
   tag string.
3. **`README.md`** → the nargo setup section points at the `t256-v0.N` tag
   used in `spartan-backend/Cargo.toml` (no per-circuit table anymore — all
   circuits always track the same tag).

Do not guess the exact tag/attribute spelling for step 1's `-M` suffix or the
flake attribute name — it has changed shape release to release (past history:
`t256-v0_1` → `commit_0c11d1` → `t256-v0_2` → `t256-v0_22` → `t256-v0_22-1`).
Confirm before editing:

```bash
# Exact git tags that exist on the noir fork for this version:
git ls-remote --tags https://github.com/eid-privacy/noir | grep 't256-v0\.N'

# Flake attribute names actually published (adjust if this errors):
nix flake show github:eid-privacy/flakes 2>&1 | grep -E 'noir-versions|barretenberg-versions|nargo-t256-versions'
```

If neither command is conclusive, `devbox update` will fail loudly naming the
bad attribute — use that as a last resort to find the right one.

## Per-version procedure

Assume the previous version's bump is already committed and CI-green before
starting the next one. Run from the repo root.

0. Editing the version strings (steps 1, 2, 4) does not require a devbox
   shell. But testing the bump (step 3 onward: `devbox update`, `devbox run
   fetch`/`build-check`/`nargo-check`/`test`/`start`/`fmt-check`) must happen
   inside a devbox shell — if `$DEVBOX_SHELL_ENABLED` is not set when you
   reach step 3, ask the user to run `devbox shell` before continuing, don't
   try to work around it.
1. Resolve the exact tag/attribute strings for target beta_N as above.
2. Edit `devbox.json`: bump all three flake refs together.
3. `devbox update` — regenerates `devbox.lock`.
4. Edit `spartan-backend/Cargo.toml`: bump the tag on all five git deps
   (they must stay identical to each other):
   ```bash
   sed -i '' 's/tag = "t256-v0\.OLD.*"/tag = "t256-v0.NEW"/' spartan-backend/Cargo.toml
   ```
5. `devbox run fetch` — pulls the new crates and rewrites `Cargo.lock`. Watch
   for dependency resolution failures here first.
6. `devbox run build-check` — full workspace build with warnings as errors.
   Fix any compile breaks caused by upstream API changes before moving on;
   don't paper over them with `allow` attributes.
7. `devbox run test` and `devbox run start` — unit tests and the end-to-end
   circuit run.
   - **Known pre-existing exception:** `c0102_signature_vanilla_equation`
     panics at the final `verify()` step ("Public inputs mismatch") on
     baseline, unrelated to any version bump — `prove()` completes fine, only
     the verify-step public-input comparison is broken. Treat "prove()
     completes without panic" as c0102's signal, not verify(). The real
     green/red gate is: c0000–c0101 pass end-to-end, c0102 reaches prove()
     without panicking.
8. `devbox run fmt-check`.
9. Commit this single beta bump on its own (devbox.json, devbox.lock,
    spartan-backend/Cargo.toml, spartan-backend/Cargo.lock, any regenerated
    circuit targets). Do not combine multiple beta bumps into one commit —
    one commit per N is what makes step 11 possible.
10. Only after this commit is clean, move to beta_(N+1).

## If something breaks

Bisect by reverting just `devbox.json` + `spartan-backend/Cargo.toml` to the
previous N's tags and re-running steps 6–8. If the failure disappears, it's
caused by the new noir/nargo/barretenberg version itself (report/investigate
upstream) rather than by anything else changed in this repo meanwhile.

For reference, past bumps that show the exact diff shape to expect:
`868f2f1`, `2c05e62`, `03bd39b` (`git show <sha>`).
