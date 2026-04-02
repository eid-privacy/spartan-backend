use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;

pub(crate) type E = T256HyraxEngine;
pub(crate) type Scalar = <T256HyraxEngine as Engine>::Scalar;
