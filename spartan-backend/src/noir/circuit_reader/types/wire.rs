use acir::native_types::Witness;

use crate::noir::circuit_reader::types::input_wire::InputWire;

#[derive(Debug, Copy, Clone)]
pub struct Wire {
    pub(crate) public: bool,
    pub(crate) witness: Witness,
}

impl Wire {
    pub fn new(public: bool, witness: Witness) -> Self {
        Wire { public, witness }
    }

    pub fn assign<V>(&self, value: V) -> InputWire<V> {
        InputWire::new(self.public, self.witness, value)
    }
}
