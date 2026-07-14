use vega_prover::provider::T256HyraxEngine;
use vega_prover::traits::Engine;

pub type E = T256HyraxEngine;
pub type Scalar = <T256HyraxEngine as Engine>::Scalar;
