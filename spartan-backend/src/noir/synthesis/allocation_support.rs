use acir::native_types::Witness;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use core::fmt;
use ff::PrimeField;
use std::collections::HashMap;
use std::fmt::Formatter;

pub(crate) type WitnessMap<V> = HashMap<u32, V>;

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

pub fn allocate_input<V, CS>(
    cs: &mut CS,
    witness: Witness,
    value: V,
) -> Result<AllocatedWire<V>, SynthesisError>
where
    V: PrimeField,
    CS: ConstraintSystem<V>,
{
    let allocation_result = AllocatedNum::alloc(
        cs.namespace(|| format!("input {:?}", witness.witness_index())),
        || Ok(value),
    )?;

    allocation_result.inputize(cs)?;

    Ok(AllocatedWire {
        witness,
        allocation: Ok(allocation_result),
    })
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
