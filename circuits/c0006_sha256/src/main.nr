use eid::{constants};
use sha256::sha256_var;

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    hash: [u8; 32],
) {
    // Step 1: Calculate the credential hash
    let credential_hash: [u8; 32] =
        sha256_var(credential_string.as_bytes(), constants::CREDENTIAL_LEN).into();

    println(hash);
    println(credential_hash);
    assert(credential_hash == hash);
}
