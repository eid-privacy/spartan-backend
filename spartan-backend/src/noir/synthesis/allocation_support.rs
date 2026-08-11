use core::fmt;
use std::fmt::Formatter;

use acir::native_types::Witness;
use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::PrimeField;

pub(crate) struct WitnessMap<V> {
    data: Vec<Option<V>>,
}

impl<V: fmt::Debug> fmt::Debug for WitnessMap<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (i, v) in self.data.iter().enumerate() {
            if let Some(v) = v {
                map.entry(&i, v);
            }
        }
        map.finish()
    }
}

impl<V> WitnessMap<V> {
    pub fn new(max_index: u32) -> Self {
        let size = max_index as usize + 1;
        WitnessMap {
            data: (0..size).map(|_| None).collect(),
        }
    }

    pub fn insert(&mut self, idx: u32, value: V) {
        self.data[idx as usize] = Some(value);
    }

    pub fn get(&self, idx: &u32) -> Option<&V> {
        self.data.get(*idx as usize)?.as_ref()
    }
}

pub(crate) struct AllocatedWire<V: PrimeField> {
    pub witness: Witness,
    // witness might be missing when synthesis is done by the verifier, SynthesisError is the
    // way the library handles this.
    pub allocation: Result<AllocatedNum<V>, SynthesisError>,
}

impl<V: PrimeField> fmt::Display for AllocatedWire<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.allocation {
            Ok(ref allocation) => f
                .debug_struct("AllocatedWire")
                .field("Witness", &self.witness)
                .field("AllocatedNum variable", &allocation.get_variable())
                .field("AllocatedNum value", &allocation.get_value())
                .finish(),
            Err(_) => f
                .debug_struct("AllocatedWire")
                .field("Witness", &self.witness)
                .field("AllocatedNum variable", &"Unallocated")
                .field("AllocatedNum value", &"Unallocated")
                .finish(),
        }
    }
}

impl<V: PrimeField> fmt::Debug for AllocatedWire<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub fn allocate_witness<V, CS>(
    cs: &mut CS,
    witness: Witness,
    value: Option<V>,
) -> Result<AllocatedWire<V>, SynthesisError>
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

    Ok(AllocatedWire {
        witness,
        // this used to be a SynthesisError that was used for verifier-side synthesis
        allocation: allocation_result,
    })
}
