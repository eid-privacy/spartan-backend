mod const;
use const::{NBR_INPUTS_PRIVATE, NBR_ASSERTS};

fn main(
    // Private inputs - "secret" number
    private_numbers: [u8; NBR_INPUTS_PRIVATE],
    // Public inputs
    public_sum: u64,
) {
    assert(NBR_ASSERTS <= NBR_INPUTS_PRIVATE);

    let mut sum: u64 = 0;
    for i in 0..NBR_INPUTS_PRIVATE {
        sum = sum + private_numbers[i] as u64;
        if i < NBR_ASSERTS {
            assert(private_numbers[i] == (i % 256) as u8);
        }
    }
    assert(sum == public_sum);
}

#[test]
fn test_main() {
    let mut input: [u8; NBR_INPUTS_PRIVATE] = [ 0; NBR_INPUTS_PRIVATE ];
    let mut sum = 0;
    for i in 0..NBR_INPUTS_PRIVATE {
        input[i] = (i % 256) as u8;
        sum += input[i] as u64;
    }
    main(input, sum);
}
