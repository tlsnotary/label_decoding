pub mod onetimesetup;
pub mod poseidon;
pub mod provernode;
pub mod verifiernode;

#[cfg(test)]
mod tests {
    use super::onetimesetup::OneTimeSetup;
    use super::provernode::Prover;
    use super::verifiernode::Verifier;
    use crate::tests::fixtures::e2e_test;

    #[test]
    fn snarkjs_e2e_test() {
        let prover_ots = OneTimeSetup::new();
        let verifier_ots = OneTimeSetup::new();

        // The Prover should have generated the proving key (before the labelsum
        // protocol starts) like this:
        prover_ots.setup().unwrap();
        let proving_key = prover_ots.get_proving_key().unwrap();

        // The Verifier should have generated the verifying key (before the labelsum
        // protocol starts) like this:
        verifier_ots.setup().unwrap();
        let verification_key = verifier_ots.get_verification_key().unwrap();

        let prover = Box::new(Prover::new(proving_key));
        let verifier = Box::new(Verifier::new(verification_key));
        e2e_test(prover, verifier);
    }
}
