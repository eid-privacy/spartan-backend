use std::{error::Error, fmt, io};

use vega_prover::errors::VegaError;

#[derive(Debug)]
pub enum BackendError {
    Setup(VegaError),
    Save(io::Error),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(e) => write!(f, "Setup error: {}", e),
            Self::Save(e) => write!(f, "Save error: {}", e),
        }
    }
}

impl Error for BackendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Setup(e) => Some(e),
            Self::Save(e) => Some(e),
        }
    }
}

impl From<VegaError> for BackendError {
    fn from(e: VegaError) -> Self {
        Self::Setup(e)
    }
}

impl From<io::Error> for BackendError {
    fn from(e: io::Error) -> Self {
        Self::Save(e)
    }
}
