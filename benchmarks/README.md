# Benchmark directories

- c9000_benchmark - trying out various optimisations with various
  circuit lengths
- swiyu_jwt - running the same circuit on various commits and noir
  versions - on a dual-core server
- swiyu_jwt_mac - same as `swiyu_jwt`, but running on a Mac M2 Max
  with 64GB of RAM
- swiyu_jwt_precompute - barretenberg vs. only the online part of
  spartan proving (after `--precompute`) across commits - on the same
  server as `swiyu_jwt`
