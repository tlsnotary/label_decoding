use group::ff::Field;
/// Specs which halo2 uses to compute a Poseidon hash both inside the zk
/// circuit and in the clear.
///
///
use halo2_gadgets::poseidon::primitives::Spec;
use pasta_curves::Fp;

// Poseidon spec for 15-rate Poseidon
#[derive(Debug, Clone, Copy)]
pub struct Spec15;

impl Spec<Fp, 16, 15> for Spec15 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
}

// Poseidon spec for 1-rate Poseidon
#[derive(Debug, Clone, Copy)]
pub struct Spec1;

impl Spec<Fp, 2, 1> for Spec1 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
}
