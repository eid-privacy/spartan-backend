use acir::native_types::Witness;

#[derive(Debug, Clone, Copy)]
pub struct InputWire<V> {
    pub public: bool,
    pub witness: Witness,
    pub value: V,
}

impl<V> InputWire<V> {
    pub fn new(public: bool, witness: Witness, value: V) -> Self {
        Self { witness, value, public }
    }

    pub fn clone_with_value<W>(&self, value: W) -> InputWire<W> {
        InputWire {
            public: self.public,
            witness: self.witness,
            value,
        }
    }
}