pub mod constants;
pub mod field_utils;
pub mod fast_base64;

pub global REVOCATION_LIST_LENGTH_WO_SIG: u32 = 8 + 8 + constants::REVOCATION_LIST_IDS / 8;
pub global REVOCATION_LIST_LENGTH: u32 = REVOCATION_LIST_LENGTH_WO_SIG + 64;
pub global REVOCATION_LIST_VALIDITY: u64 = 86400 * 7;

pub fn slice<let IN: u32, let OUT: u32>(input: [u8; IN], start: u32) -> [u8; OUT] {
    let mut out = [0u8; OUT];
    for i in 0..OUT {
        out[i] = input[start + i];
    }
    out
}

pub fn hex_to_u64<let LEN: u32>(hex_str: [u8; LEN], start: u32) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        let high_nibble = decode_nibble(hex_str[start + 2 * i]);
        let low_nibble = decode_nibble(hex_str[start + 2 * i + 1]);
        result = (result << 8) + ((high_nibble << 4) + low_nibble) as u64;
    }
    result
}

pub fn decode_hex_32<let LEN: u32>(hex_str: [u8; LEN], start: u32) -> [u8; 32] {
    let mut result: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        let high_nibble = decode_nibble(hex_str[start + 2 * i]);
        let low_nibble = decode_nibble(hex_str[start + 2 * i + 1]);
        result[i] = high_nibble * 16 + low_nibble;
    }
    result
}

fn decode_nibble(hex_char: u8) -> u8 {
    (hex_char & 0x0F) + (hex_char >> 6) * 9
}

pub fn move_right<let N: u32, let LOG: u32>(src: [u8; N], shift: u32) -> [u8; N] {
    let mut rest = shift;
    let mut cur = src;
    let mut step: u32 = 1;
    for _k in 0..LOG {
        let bit = rest % 2; // `%` / `/` rather than bitwise: no BLACKBOX::AND
        rest = rest / 2;
        let mut next: [u8; N] = [0; N];
        for i in 0..N {
            let from = if i >= step { cur[i - step] } else { 0 };
            next[i] = if bit == 1 { from } else { cur[i] };
        }
        cur = next;
        step *= 2;
    }
    assert(rest == 0, "move out of range");
    cur
}

pub fn move_right_simple<let N: u32>(src: [u8; N], shift: u32) -> [u8; N] {
    let mut out: [u8; N] = [0; N];
    for k in 0..N {
        if k >= shift {
            out[k] = src[k - shift]
        }
    }
    out
}
