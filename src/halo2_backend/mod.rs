pub mod circuit;
pub mod onetimesetup;
pub mod poseidon_spec;
pub mod prover;
pub mod utils;

use crate::halo2_backend::onetimesetup::OneTimeSetup;
use crate::halo2_backend::utils::u8vec_to_boolvec;
use rand::{thread_rng, Rng};
#[test]
fn e2e_test() {
    let mut rng = thread_rng();

    let ots = OneTimeSetup::new();

    // The Prover should have generated the proving key (before the labelsum
    // protocol starts) like this:
    ots.setup().unwrap();
    let proving_key = ots.get_proving_key();

    // generate random plaintext of random size up to 2000 bytes
    let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
        .take(thread_rng().gen_range(0..300))
        .collect();

    // Normally, the Prover is expected to obtain her binary labels by
    // evaluating the garbled circuit.
    // To keep this test simple, we don't evaluate the gc, but we generate
    // all labels of the Verifier and give the Prover her active labels.
    let bit_size = plaintext.len() * 8;
    let mut all_binary_labels: Vec<[u128; 2]> = Vec::with_capacity(bit_size);
    let mut delta: u128 = rng.gen();
    // set the last bit
    delta |= 1;
    for _ in 0..bit_size {
        let label_zero: u128 = rng.gen();
        all_binary_labels.push([label_zero, label_zero ^ delta]);
    }
    let prover_labels = choose(&all_binary_labels, &u8vec_to_boolvec(&plaintext));

    let verifier = LabelsumVerifier::new(
        all_binary_labels.clone(),
        Box::new(verifiernode::VerifierNode {}),
    );

    let verifier = verifier.setup().unwrap();

    let prover = LabelsumProver::new(
        proving_key,
        prime,
        plaintext,
        poseidon,
        Box::new(provernode::ProverNode {}),
    );

    // Perform setup
    let prover = prover.setup().unwrap();

    // Commitment to the plaintext is sent to the Notary
    let (plaintext_hash, prover) = prover.plaintext_commitment().unwrap();

    // Notary sends back encrypted arithm. labels.
    let (cipheretexts, verifier) = verifier.receive_plaintext_hashes(plaintext_hash);

    // Hash commitment to the label_sum is sent to the Notary
    let (label_sum_hashes, prover) = prover
        .labelsum_commitment(cipheretexts, &prover_labels)
        .unwrap();

    // Notary sends the arithmetic label seed
    let (seed, verifier) = verifier.receive_labelsum_hashes(label_sum_hashes);

    // At this point the following happens in the `committed GC` protocol:
    // - the Notary reveals the GC seed
    // - the User checks that the GC was created from that seed
    // - the User checks that her active output labels correspond to the
    // output labels derived from the seed
    // - we are called with the result of the check and (if successful)
    // with all the output labels

    let prover = prover
        .binary_labels_authenticated(true, Some(all_binary_labels))
        .unwrap();

    // Prover checks the integrity of the arithmetic labels and generates zero_sums and deltas
    let prover = prover.authenticate_arithmetic_labels(seed).unwrap();

    // Prover generates the proof
    let (proofs, prover) = prover.create_zk_proof().unwrap();

    // Notary verifies the proof
    let verifier = verifier.verify_many(proofs).unwrap();
    assert_eq!(
        type_of(&verifier),
        "labelsum::verifier::LabelsumVerifier<labelsum::verifier::VerificationSuccessfull>"
    );
}

/// Unzips a slice of pairs, returning items corresponding to choice
fn choose<T: Clone>(items: &[[T; 2]], choice: &[bool]) -> Vec<T> {
    assert!(items.len() == choice.len(), "arrays are different length");
    items
        .iter()
        .zip(choice)
        .map(|(items, choice)| items[*choice as usize].clone())
        .collect()
}

fn type_of<T>(_: &T) -> &'static str {
    std::any::type_name::<T>()
}
