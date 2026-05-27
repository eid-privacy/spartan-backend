use crate::Scalar;

#[derive(Clone, PartialEq, Debug)]
pub enum NamedCurve {
    /// NIST-P256
    Secp256r1,
}

#[derive(Clone)]
pub struct ECDSAParams {
    /// Enum that indicates which curve the signature is on
    pub curve: NamedCurve,
    /// x-coord of group generator point
    pub g_x: Scalar,
    /// y-coord of group generator point
    pub g_y: Scalar,
}

#[derive(Clone)]
pub struct Point<T> {
    pub x: T,
    pub y: T
}

impl ECDSAParams {
    pub fn new(g_x: Scalar, g_y: Scalar) -> Self {
        Self {
            curve: NamedCurve::Secp256r1,
            g_x,
            g_y
        }
    }
}