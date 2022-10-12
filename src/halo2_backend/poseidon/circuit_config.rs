use halo2_gadgets::poseidon::primitives::Spec;
use halo2_gadgets::poseidon::Pow5Chip;
use halo2_gadgets::poseidon::Pow5Config;
use halo2_proofs::plonk::ConstraintSystem;
use pasta_curves::pallas::Base as F;

/// Configures the in-circuit Poseidon for rate 15 and returns the config
///
/// Patterned after [halo2_gadgets::poseidon::pow5]
/// (see in that file tests::impl Circuit for HashCircuit::configure())
pub fn configure_poseidon_rate_15<S: Spec<F, 16, 15>>(
    rate: usize,
    meta: &mut ConstraintSystem<F>,
) -> Pow5Config<F, 16, 15> {
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
) -> Pow5Config<F, 2, 1> {
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
