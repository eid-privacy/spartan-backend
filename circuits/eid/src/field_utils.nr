use std::field::t256::P256Point;

// Size of a T256 field element decomposed into bytes
pub global T256_SCALAR_SIZE: u32 = 32;

pub fn array_to_field(arr: [u8; 32]) -> Field {
    let mut field_value: Field = 0;
    for i in 0..32 {
        field_value = field_value * 256 + arr[i] as Field;
    }
    field_value
}

// Enforce key ECDSA equation parameters to be in valid ranges
// Typically, > 0 and < n.
// From Noir's construction, `Field` variables are already reduced (mod n)
pub fn enforce_ecdsa_parameters(s_inv_jwt: Field, R_jwt: P256Point) {
    assert(not_zero(s_inv_jwt));
    assert(not_zero(R_jwt.x) & not_zero(R_jwt.y));
}

fn not_zero(x: Field) -> bool {
    !x.eq(0)
}
