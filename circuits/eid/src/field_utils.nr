// Size of a T256 field element decomposed into bytes
pub global T256_SCALAR_SIZE: u32 = 32;

pub fn array_to_field(arr: [u8; 32]) -> Field {
    let mut field_value: Field = 0;
    for i in 0..32 {
        field_value = field_value * 256 + arr[i] as Field;
    }
    field_value
}

unconstrained pub fn split_point(point: [u8; 64]) -> (Field, Field) {
    let mut lo_bytes: [u8; 32] = [0; 32];
    let mut hi_bytes: [u8; 32] = [0; 32];

    for i in 0..32 {
        lo_bytes[i] = point[i];
        hi_bytes[i] = point[i + 32];
    }

    (array_to_field(lo_bytes), array_to_field(hi_bytes))
}