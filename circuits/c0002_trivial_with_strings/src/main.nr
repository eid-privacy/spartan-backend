fn main(
    // Private inputs - "secret" number
    private_number: str<12>,
    // Public inputs
    public_number: pub str<12>,
) {
    assert(private_number == public_number);
}
