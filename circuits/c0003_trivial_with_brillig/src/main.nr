fn main(
    // Private inputs - "secret" number
    private_number: Field,
    // Public inputs
    public_number: pub Field,
) {
    // Safety: we don't really need that :)
    let with_added = unsafe { unconstrained_add(private_number, 1) };
    // this is for the "unconstrained" warning
    assert(with_added == private_number + 1);

    assert(with_added == public_number);
}

unconstrained fn unconstrained_add(v0: Field, v1: Field) -> Field {
    v0 + v1
}