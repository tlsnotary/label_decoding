use group::ff::Field;
use halo2_gadgets::poseidon::primitives::Spec;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_gadgets::poseidon::Pow5Chip;
use halo2_gadgets::poseidon::Pow5Config;
use halo2_proofs::plonk::ConstraintSystem;
use pasta_curves::pallas::Base as F;
use pasta_curves::Fp;

/// Spec for rate 15 Poseidon which halo2 uses both inside
/// the zk circuit and in the clear.
///
/// Compare it to the spec which zcash uses:
/// [halo2_gadgets::poseidon::primitives::P128Pow5T3]
#[derive(Debug)]
pub struct Spec15;

impl Spec<Fp, 16, 15> for Spec15 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        // Taken from https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
        // (see "var N_ROUNDS_P[16]"), where they use 64 partial rounds for 15-rate Poseidon
        64
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    /// TODO: waiting on a definitive answer if returning 0 here is safe
    /// https://github.com/zcash/halo2/issues/674
    fn secure_mds() -> usize {
        0
    }
}

/// Spec for rate 1 Poseidon which halo2 uses both inside
/// the zk circuit and in the clear.
///
/// Compare it to the spec which zcash uses:
/// [halo2_gadgets::poseidon::primitives::P128Pow5T3]
#[derive(Debug)]
pub struct Spec1;

impl Spec<Fp, 2, 1> for Spec1 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        // Taken from https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
        // (see "var N_ROUNDS_P[16]"), where they use 56 partial rounds for 1-rate Poseidon
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    /// TODO: waiting on a definitive answer if returning 0 here is safe
    /// https://github.com/zcash/halo2/issues/674
    fn secure_mds() -> usize {
        0
    }
}

/// Hashes inputs with rate 15 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_15(field_elements: &[F; 15]) -> F {
    poseidon::Hash::<F, Spec15, ConstantLength<15>, 16, 15>::init().hash(*field_elements)
}

/// Hashes inputs with rate 1 Poseidon and returns the digest
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::poseidon_hash())
pub fn poseidon_1(field_elements: &[F; 1]) -> F {
    poseidon::Hash::<F, Spec1, ConstantLength<1>, 2, 1>::init().hash(*field_elements)
}

/// Configures the in-circuit Poseidon for rate 15 and returns the config
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::impl Circuit for HashCircuit::configure())
pub fn configure_poseidon_rate_15<S: Spec<F, 16, 15>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<Fp, 16, 15> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    meta.enable_constant(rc_b[0]);

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}

/// Configures the in-circuit Poseidon for rate 1 and returns the config
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::impl Circuit for HashCircuit::configure())
pub fn configure_poseidon_rate_1<S: Spec<F, 2, 1>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<Fp, 2, 1> {
    let width = rate + 1;
    let state = (0..width).map(|_| meta.advice_column()).collect::<Vec<_>>();
    let partial_sbox = meta.advice_column();

    let rc_a = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    let rc_b = (0..width).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    meta.enable_constant(rc_b[0]);

    Pow5Chip::configure::<S>(
        meta,
        state.try_into().unwrap(),
        partial_sbox,
        rc_a.try_into().unwrap(),
        rc_b.try_into().unwrap(),
    )
}
