fn main(
    // Private inputs - "secret" number
    private_number: Field,
    // Public inputs
    public_number: pub Field,
) {
    assert(private_number == public_number);
}
