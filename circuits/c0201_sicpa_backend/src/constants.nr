/// Maximum raw JWT payload length in bytes.
/// SD-JWT payloads are smaller than full JWT payloads because disclosable claims
/// are replaced by SHA-256 digests in the `_sd` array.
pub global PAYLOAD_MAX_LEN: u32 = 2048;

/// Maximum decoded disclosure length in bytes.
/// A disclosure is a JSON array: ["salt","claim_name",claim_value]
/// e.g. ["abc123def456789012345w","dob",23331000]
pub global DISCLOSURE_MAX_LEN: u32 = 128;

/// `encode_url_into` requires its input length to be a multiple of 3; round
/// `DISCLOSURE_MAX_LEN` up to the next one.
pub global DISCLOSURE_ENCODE_IN_LEN: u32 = ((DISCLOSURE_MAX_LEN + 2) / 3) * 3;
/// Matches the number of bytes `encode_url_into` writes for
/// `DISCLOSURE_ENCODE_IN_LEN`: `(n / 3) * 4`.
pub global DISCLOSURE_ENCODED_MAX_LEN: u32 = (DISCLOSURE_ENCODE_IN_LEN * 4) / 3;

/// Maximum salt length in bytes (base64 encoded).
pub global DOB_SALT_MAX_LEN: u32 = 32;

/// Maximum value length in bytes (e.g. "1988-06-19" = 10).
pub global DOB_VALUE_MAX_LEN: u32 = 16;

/// DOB claim name in SD-JWT disclosure format. Swiss eID uses "birth_date".
pub global DOB_CLAIM_NAME: [u8; 10] = "birth_date".as_bytes();

/// base64url-encoded length of a 32-byte value: ceil(32 * 4 / 3).
pub global COORD_BASE64_LEN: u32 = 43;

/// Minimum age in years required for the age gate.
pub global MIN_AGE_YEARS: u32 = 25;

/// Maximum length of the encoded JWT header in bytes.
pub global ENCODED_HEADER_MAX_LEN: u32 = 128;
