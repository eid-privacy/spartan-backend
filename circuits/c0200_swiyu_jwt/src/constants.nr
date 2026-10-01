/// Maximum raw JWT payload length in bytes.
/// SD-JWT payloads are smaller than full JWT payloads because disclosable claims
/// are replaced by SHA-256 digests in the `_sd` array.
pub global PAYLOAD_MAX_LEN: u32 = 1911;

/// Maximum salt length in bytes (base64url-encoded, no padding): a 16-byte
/// (128-bit) random salt is the standard SD-JWT salt size, encoding to
/// exactly ceil(16*4/3) = 22 base64url characters.
pub global DOB_SALT_MAX_LEN: u32 = 22;

/// Maximum value length in bytes. `birth_date_as_int` only ever reads
/// indices 0..9 of this field (a fixed "YYYY-MM-DD" layout), so any capacity
/// above 10 is unused padding.
pub global DOB_VALUE_MAX_LEN: u32 = 10;

/// DOB claim name in SD-JWT disclosure format. Swiss eID uses "birth_date".
pub global DOB_CLAIM_NAME: [u8; 10] = "birth_date".as_bytes();

/// Maximum decoded disclosure length in bytes.
/// A disclosure is a JSON array: ["salt","claim_name",claim_value]
/// e.g. ["abc123def456789012345w","dob",23331000]
/// = 2 ('["') + salt + 3 ('","') + claim_name (10) + 3 ('","') + value + 2 ('"]')
pub global DISCLOSURE_MAX_LEN: u32 = 20 + DOB_SALT_MAX_LEN + DOB_VALUE_MAX_LEN;

/// base64url-encoded length of a 32-byte value: ceil(32 * 4 / 3).
pub global COORD_BASE64_LEN: u32 = 43;

/// Minimum age in years required for the age gate.
pub global MIN_AGE_YEARS: u32 = 25;
