# Circuits for testing spartan-backend

The circuits in here are used to test and benchmark the spartan
backend.
These are the main groups:

- `c0000`..`c0099` - circuits from the [zkp-pocs](https://github.com/eid-privacy/zkp-pocs)
repository
- `c0100`..`c0999` - circuits specifically for the spartan-backend
using the optimisations
- `c9000`..`c9999` - circuits used for benchmarking only

Note: circuits involving a verifier-provided nonce for proof-of-possession are designed as-is for implementation
conciseness. A more robust implementation to avoid public key extraction would involve making sure the nonce is unique
(e.g., using a timestamp, having the prover append a random value to the verifier nonce, etc.)

## SICPA-backend circuits c0201-c0203

We have the following circuits for the SICPA backend.
All three are based on the `c0200_swiyu_jwt` circuit, but add
a header which contains the public key of the issuer.

- `c0201_sicpa_backend` - the straightforward implementation,
  but very heavy due to the conversion of an input witness
  to a memory. This increases the number of constraints for
  spartan by a factor of 18!
- `c0202_sicpa_backend_constant` - supposing the header is
  constant size, and only the content of the public key
  changes, this is the simplest solution to get back to a
  similar number of constraints as `c0200_swiyu_jwt`
- `c0202_sicpa_backend_move` - a proposal by Claude to change
  the way the conversion to base64 is done allows to keep
  a variable-length header input, with only a modest
  10% increase in the number of constraints compared to
  `c0200_swiyu_jwt`.
