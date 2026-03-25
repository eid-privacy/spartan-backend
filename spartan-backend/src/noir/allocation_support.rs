use core::fmt;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::ops::{Deref, DerefMut};
use acir::native_types::Witness;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::PrimeField;

#[derive(Debug, Clone)]
pub struct WitnessMap<V> {
    pub map: HashMap<u32, V>,
}

// might remove this or make it typealias since the utility methods gradually disappeared
impl<V> WitnessMap<V> {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn add(&mut self, witness: Witness, value: V) {
        self.map.insert(witness.witness_index(), value);
    }
}

impl<V> Deref for WitnessMap<V> {
    type Target = HashMap<u32, V>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<V> DerefMut for WitnessMap<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

#[derive(Clone, Debug)]
pub struct FunctionParameter<V> {
    pub index: u32,
    pub witness: Witness,
    pub name: String,
    pub public: bool,
    pub value: Option<V>
}

impl <V> FunctionParameter<V> {
    pub fn new(index: u32, witness: Witness, name: String, public: bool, value: Option<V>) -> Self {
        Self { index, witness, name, public, value }
    }
}

pub struct AllocatedWire<V: PrimeField> {
    pub witness: Witness,
    // witness might be missing when synthesis is done by the verifier, SynthesisError is the
    // way the library handles this.
    pub allocation: Result<AllocatedNum<V>, SynthesisError>,
}

impl <V: PrimeField> fmt::Display for AllocatedWire<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // This can panic for verifiers with unallocated witness values. Handle more gracefully
        f.debug_struct("AllocatedWire")
            .field("Witness", &self.witness)
            .field("AllocatedNum variable", &self.allocation.as_ref().unwrap().get_variable())
            .field("AllocatedNum value", &self.allocation.as_ref().unwrap().get_value())
            .finish()
    }
}

impl <V: PrimeField> fmt::Debug for AllocatedWire<V> {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub fn allocate_input<V, CS>(
    cs: &mut CS,
    witness: Witness,
    value: V,
) -> AllocatedWire<V>
where
    V: PrimeField,
    CS: ConstraintSystem<V>,
{
    // Placeholder for input allocation logic
    let allocation_result = AllocatedNum::alloc(
        cs.namespace(|| format!("input {:?}", witness.witness_index())),
        || Ok(value)
    ).expect("Failed to allocate input");


    let _ = allocation_result.inputize(cs);

    AllocatedWire {
        witness,
        allocation: Ok(allocation_result),
    }
}

pub fn allocate_witness<V, CS>(
    cs: &mut CS,
    witness: Witness,
    value: Option<V>,
) -> AllocatedWire<V>
where
    V: PrimeField,
    CS: ConstraintSystem<V>,
{
    let allocation_result = AllocatedNum::alloc(
        cs.namespace(|| format!("witness {:?}", witness.witness_index())),
        || match value {
            Some(v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing),
        },
    );

    AllocatedWire {
        witness,
        allocation: allocation_result,
    }
}