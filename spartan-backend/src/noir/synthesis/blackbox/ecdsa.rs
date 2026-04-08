use acir::circuit::opcodes::FunctionInput;
use acir::circuit::opcodes::FunctionInput::Constant;
use acir::FieldElement;
use acir::native_types::{Witness};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use num_bigint::BigUint;
use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::types::Scalar;
use crate::utils::{big_to_ff, hex_to_big, hex_to_ff, scalar_to_biguint};

struct ECDSAParameters {
    g_x: Scalar,
    g_y: Scalar,
    n: Scalar,
    n_big: BigUint,
}

impl ECDSAParameters {
    pub fn new() -> Self {
        Self {
            g_x: hex_to_ff("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            g_y: hex_to_ff("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            n: hex_to_ff("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            n_big: hex_to_big("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        }
    }
}

pub struct ECDSAVerifier<'a> {
    allocation_store: &'a WitnessMap<AllocatedWire<Scalar>>,
    ecdsa_parameters: ECDSAParameters,
}

impl<'a> ECDSAVerifier<'a> {
    pub fn new(allocation_store: &'a WitnessMap<AllocatedWire<Scalar>>) -> Self {
        Self {
            allocation_store,
            ecdsa_parameters: ECDSAParameters::new()
        }
    }

    fn mod_inverse(a: &BigUint, p: &BigUint) -> BigUint {
      let two = BigUint::from(2u8);
      a.modpow(&(p - two), p)
    }

    fn recombine(&self, inputs: &[FunctionInput<FieldElement>]) -> Scalar {
        let mut recombined_value = Scalar::zero();
        for input in inputs.iter() {
            match input {
                Constant(element) => recombined_value += to_spartan_scalar::<Scalar>(element),
                FunctionInput::Witness(witness) => {
                    let allocated_witness = self.allocation_store
                        .get(&witness.witness_index()).unwrap();
                    // TODO: handle all this unwrapping mess
                    let allocation_value = self.allocation_store
                        .get(&witness.witness_index()).unwrap()
                        .allocation.as_ref().unwrap()
                        .get_value().unwrap();

                    recombined_value += allocation_value;
                }
            }
        }
        recombined_value
    }

    pub fn verify_secp256r1_signature<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        public_key_x: &Box<[FunctionInput<FieldElement>; 32]>,
        public_key_y: &Box<[FunctionInput<FieldElement>; 32]>,
        signature: &Box<[FunctionInput<FieldElement>; 64]>,
        hashed_message: &Box<[FunctionInput<FieldElement>; 32]>,
        // from Noir documentation: output: 0 for failure and 1 for success
        output: &Witness,
    ) -> Result<(), SynthesisError> {
        // Step 1: proving public key is valid
        let pub_x = self.recombine(&public_key_x[..]);
        let pub_y = self.recombine(&public_key_y[..]);
        //   check public_key != O
        assert_ne!(pub_x, Scalar::zero());
        assert_ne!(pub_y, Scalar::zero());
        //   check public_key is on the curve
        //   check n*public_key = O
        assert_ne!(pub_x * self.ecdsa_parameters.n, Scalar::zero());
        assert_ne!(pub_y * self.ecdsa_parameters.n, Scalar::zero());

        // Step 2: verifying the signature
        let r = self.recombine(&signature[..32]);
        let s = self.recombine(&signature[32..]);
        //  - assert r, s in [1, n-1]
        //  - get LMB_n(hash). With P-256 and SHA-256 we have LBigUint MB_n(hash) == hash
        let hash_element= self.recombine(&hashed_message[..]);

        let s_inverse = Self::mod_inverse(
            &scalar_to_biguint(&s),
            &self.ecdsa_parameters.n_big,
        );
        let s_inverse_ff: Scalar = big_to_ff(&s_inverse);

        //  - (x_1, x_2) = u_1 x G + u_2 x G
        //  - u1 = zs^(-1) mod n
        let u1 = s_inverse_ff * hash_element;
        //  - u2 = zs^(-1) mod n
        let u2 = s_inverse_ff * r;

        // this can be optimized using "Shamir's trick" ? See wikipedia
        let x1 = u1 * self.ecdsa_parameters.g_x + u2 * pub_x;
        let x2 = u1 * self.ecdsa_parameters.g_y + u2 * pub_y;

        //  assert (x_1, x_2) != O
        assert_ne!(x1, Scalar::zero());
        assert_ne!(x2, Scalar::zero());

        //  assert r = x_1 mod n
        assert_eq!(r, x1);
        Ok(())
    }
}