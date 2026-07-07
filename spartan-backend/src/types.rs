use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;

pub type E = T256HyraxEngine;
pub type Scalar = <T256HyraxEngine as Engine>::Scalar;
