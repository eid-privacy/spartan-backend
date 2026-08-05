use vega_prover::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <T256HyraxEngine as Engine>::Scalar;
