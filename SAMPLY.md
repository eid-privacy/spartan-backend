# Profiling the Spartan backend with samply

[samply](https://github.com/mstange/samply) is a sampling profiler. We use it to
find hotspots in the `spartan-backend` binary while it creates and verifies a
proof for a given circuit. The results are shown as a flamegraph / call tree in
the Firefox Profiler UI, which samply opens in your browser.

`samply` is provided by `devbox.json`, so it is available inside a `devbox shell`.

## Running

```bash
./scripts/samply.sh <circuit-match>
# or, via devbox:
devbox run samply <circuit-match>
```

`<circuit-match>` is a substring of a circuit directory name under `circuits/`.
For example, to profile `circuits/c0006_sha256`:

```bash
./scripts/samply.sh 06
# or
./scripts/samply.sh sha256
# or
devbox run samply 06
```

The script:

1. Resolves the circuit directory from the partial match (errors out if the
   match is empty or ambiguous).
2. Builds `spartan-backend` with the `profiling` Cargo profile (release
   optimizations **plus** debug symbols, so stacks are readable).
3. Records a profile with samply while the binary proves and verifies the
   circuit, saving it to `scripts/samply/<circuit>.json.gz`.
4. Opens the Firefox Profiler UI in your browser, where the **Flame Graph**,
   **Stack Chart**, and **Call Tree** tabs show the hotspots.

Any extra arguments are forwarded to `samply record`, e.g. to raise the sampling
rate:

```bash
./scripts/samply.sh sha256 -r 2000
# or
devbox run samply sha256 -r 2000
```

## Re-opening a saved profile

Recorded profiles live in `scripts/samply/` (git-ignored). To reopen one without
re-running the workload:

```bash
samply load scripts/samply/c0006_sha256.json.gz
```

## Notes

- Only circuits that already have a compiled witness (`target/*.gz`) and a
  `verifier_input.json` can be profiled. Compile one first if needed:
  `(cd circuits/<circuit> && nargo-t256 compile --force && nargo-t256 execute --force)`.
- The `profiling` build is separate from `release`, so it will not interfere
  with benchmark builds (see [BENCHMARKS.md](BENCHMARKS.md)).
