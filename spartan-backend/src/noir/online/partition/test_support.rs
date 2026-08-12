//! Hand-built ACIR fragments shared by the partition unit tests.
//!
//! They keep the tests independent from any compiled circuit artifact, so the
//! taint and segment logic can be exercised without `nargo`.

use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit, Opcode, PublicInputs,
        brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
    },
    native_types::{Expression, Witness},
};

/// A circuit made of `opcodes` whose `private` witnesses are circuit inputs
/// (i.e. known to the solver before the first opcode runs).
pub fn circuit(opcodes: Vec<Opcode<FieldElement>>, private: &[u32]) -> Circuit<FieldElement> {
    Circuit {
        function_name: "test".to_string(),
        opcodes,
        private_parameters: private.iter().map(|w| Witness(*w)).collect::<BTreeSet<_>>(),
        public_parameters: PublicInputs(BTreeSet::new()),
        return_values: PublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
    }
}

/// The single-witness expression `w`.
pub fn single(w: u32) -> Expression<FieldElement> {
    Expression {
        mul_terms: Vec::new(),
        linear_combinations: vec![(FieldElement::one(), Witness(w))],
        q_c: FieldElement::zero(),
    }
}

/// The constraint `a + b - c = 0`: it reads `a` and `b` and, once they are
/// known, the solver derives `c` from it.
pub fn linear(a: u32, b: u32, c: u32) -> Opcode<FieldElement> {
    Opcode::AssertZero(Expression {
        mul_terms: Vec::new(),
        linear_combinations: vec![
            (FieldElement::one(), Witness(a)),
            (FieldElement::one(), Witness(b)),
            (-FieldElement::one(), Witness(c)),
        ],
        q_c: FieldElement::zero(),
    })
}

/// A Brillig call reading `input` and declaring `outputs` as its writes.
pub fn brillig(input: u32, outputs: &[u32]) -> Opcode<FieldElement> {
    Opcode::BrilligCall {
        id: BrilligFunctionId::new(0),
        inputs: vec![BrilligInputs::Single(single(input))],
        outputs: outputs
            .iter()
            .map(|w| BrilligOutputs::Simple(Witness(*w)))
            .collect(),
        predicate: Expression::default(),
    }
}
