fn main(
    // Private inputs - "secret" number
    private_number: u8,
    // Public inputs
    public_number: pub u8,
) {
    assert(private_number == public_number);
}
