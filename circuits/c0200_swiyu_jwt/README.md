# Experiment Background

This experiment runs on an SD-JWT object that was obtained from the
Swiyu E-ID demo issuer. `./data/credential-sdjwt.txt`

However, in order to do our device binding experiment, we needed to modify
the CNF claim, and add our own public key there.
The result is `./data/sdjwt-payload.json`

Then it got signed using the tools in
https://github.com/eid-privacy/noir-experiments/tree/main/circuits/tools,
as described in
https://github.com/eid-privacy/noir-experiments/blob/main/circuits/jwt-swiyu/experiment50/README.md

The output is then used in the `Prover.toml`.

# Possible Optimization

To verify the signature, this circuit re-creates the BASE64-encoded
payload, and appends it to the header.
One test would be to:

- pass the base64 encoded payload, including the header, as a private input
- verify the signature
- base64 encode only the necessary parts from the input

This would reduce the memory requirements by half, as the payload would
not have to be stored fully twice.

However, Claude is not convinced:

> Verdict: The savings are real but modest — the dominant costs (ECDSA verification, SHA-256) are unchanged. The
> misalignment of existing offsets (745, 1471) means you'd need to decode slightly more than the minimum, and the circuit
> logic becomes more complex. Worth doing if you're squeezing every percent, but it won't be a dramatic improvement.

So this improvement is left as an exercise to the reader :)
