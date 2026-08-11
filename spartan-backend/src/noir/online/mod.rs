//! Precompute/online split for Noir circuits over Vega.
//!
//! ACIR emits a monolithic circuit with no notion of which witness is invariant
//! across proofs and which one changes per proof, so that boundary has to be
//! reconstructed outside Noir. [`partition`] does the first half of the work: it
//! takes the witnesses a circuit declares as online and derives, purely
//! structurally, every other witness that depends on them.

pub mod partition;
