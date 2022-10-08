pub mod circuit;
pub mod onetimesetup;
pub mod poseidon;
pub mod prover;
pub mod utils;
pub mod verifier;

/// The amount of useful bits, see [crate::prover::Prove::useful_bits].
/// This value is hard-coded into the circuit regardless of whether we use pasta
/// curves (field size 255) or the bn254 curve (field size 254).
const USEFUL_BITS: usize = 253;

/// The size of the chunk, see [crate::prover::Prove::chunk_size].
/// We use 14 field elements of 253 bits and 128 bits of the 15th field
/// element: 14 * 253 + 128 == 3670 bits total. The low 125 bits
/// of the last field element will be used for the salt.
const CHUNK_SIZE: usize = 3670;

/// The elliptic curve on which the Poseidon hash will be computed.
pub enum Curve {
    PASTA,
    BN254,
}

#[cfg(test)]
mod tests {
    use super::onetimesetup::OneTimeSetup;
    use super::prover::Prover;
    use super::verifier::Verifier;
    use super::*;
    use crate::tests::e2e_test;

    /// Run the whole authdecode protocol end-to-end, optionally corrupting the proof
    /// if `will_corrupt_proof` is set to true.
    fn halo2_e2e_test(will_corrupt_proof: bool) {
        let mut prover_ots = OneTimeSetup::new();
        let mut verifier_ots = OneTimeSetup::new();

        // The Prover should have generated the proving key (before the authdecode
        // protocol starts) like this:
        prover_ots.setup();
        let proving_key = prover_ots.get_proving_key();

        // The Verifier should have generated the verifying key (before the authdecode
        // protocol starts) like this:
        verifier_ots.setup();
        let verification_key = verifier_ots.get_verification_key();

        let prover = Box::new(Prover::new(proving_key));
        let verifier = Box::new(Verifier::new(verification_key, Curve::PASTA));
        e2e_test(prover, verifier, will_corrupt_proof);
    }

    #[test]
    /// Tests that the protocol runs successfully
    fn halo2_e2e_test_success() {
        halo2_e2e_test(false);
    }

    #[test]
    /// Tests that a corrupted proof causes verification to fail
    fn halo2_e2e_test_failure() {
        halo2_e2e_test(true);
    }
}
